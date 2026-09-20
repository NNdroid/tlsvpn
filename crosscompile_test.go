package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// linuxMatrix 与 scripts/build.sh 的 LINUX_MATRIX 保持同一份清单；改发布矩阵时两处都要动。
var linuxMatrix = []string{
	"linux/amd64",
	"linux/386",
	"linux/arm64",
	"linux/arm",
	"linux/mipsle",
	"linux/mips",
}

// TestCrossCompileLinuxMatrix 保证发布矩阵上的每个目标都能编过。
//
// 之所以单独立这个测试：`go test` 只编译宿主平台。一个两平台共用的类型或函数
// 一旦写进带 build tag 的文件，宿主这一侧照旧编译通过、测试全绿，而另一侧直接
// undefined。真出过一次——brutalStatus 定义在 tap_other.go（!linux），却被
// net_linux.go 使用，六个 Linux 目标全部编译失败，而本机 go test 一路绿灯。
// CI 里有 `GOOS=linux go vet` 兜底，但它在推送之后才跑；把矩阵编进测试套件，
// 本地 `go test` 就能在提交前拦住这类错。
func TestCrossCompileLinuxMatrix(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go 不在 PATH，跳过交叉编译检查")
	}
	dir, err := os.MkdirTemp("", "tlsvpn-xbuild")
	if err != nil {
		t.Fatalf("建临时目录失败：%v", err)
	}
	defer os.RemoveAll(dir)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []string

	for _, target := range linuxMatrix {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) != 2 {
			continue
		}
		goos, goarch := parts[0], parts[1]
		wg.Add(1)
		go func(goos, goarch string) {
			defer wg.Done()
			cmd := exec.Command(goBin, "build", "-o", filepath.Join(dir, goarch), ".")
			cmd.Env = append(os.Environ(),
				"CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
			out, err := cmd.CombinedOutput()
			if err != nil {
				mu.Lock()
				failed = append(failed, target)
				mu.Unlock()
				t.Errorf("%s 编译失败：%v\n%s", target, err, out)
			}
		}(goos, goarch)
	}
	wg.Wait()
	if len(failed) > 0 {
		t.Errorf("以下目标编译失败：%s（scripts/build.sh 的发布矩阵）",
			strings.Join(failed, ", "))
	}
}
