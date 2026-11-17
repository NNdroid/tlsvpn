/* 调度设置 UI（选路算法 + FEC parity 分发策略）。JSON 编辑器保持唯一事实来源：
   下拉/输入读写顶层 routing_algo / fec_strategy / fec_near_window_ms（全局，
   client 上行 / server 下行共用）。 */
(function(){
  'use strict';

  const pane=document.getElementById('pane-settings');
  const editor=document.getElementById('cfg-editor');
  if(!pane||!editor)return;

  const COPY={
    'zh-CN':{
      title:'调度设置',sub:'选路算法、资格门与 FEC parity 分发。热更生效，无需重启。',labelAlgo:'选路算法',labelFec:'FEC parity 分发策略',labelWindow:'near 窗口 (ms)',labelGate:'候选资格门维度',labelGateWindow:'fwd 门窗口 (ms)',
      hint:'auto=去程稳定地板+服务时间（粘滞+WFQ）；latency_strict=严格最低去程地板；latency_sticky=最低去程地板+粘滞；min_rtt_strict=严格最低无拥塞地板；min_rtt_adaptive=无拥塞地板+粘滞+WFQ；roundtrip_strict=严格最低当前往返。',
      fecHint:'auto=所有健康后端轮转（默认）；near=只投到去程单程时延与数据路径相差 ≤ 窗口的连接，抑制慢备链路的 parity 泄漏。',
      windowHint:'仅 near 生效：parity 只发给与数据路径去程时延相差 ≤ N ms 的连接。范围 1-100。',
      gateHint:'rtt=按内核 min_rtt 往返地板设门（默认，方向盲）；fwd=按本端去程排名键设门，让"去程最快但往返很慢"的极不对称路径也能准入——它慢的那一侧是对端发送方向，由对端自己的门挡掉。两端各自按发送方向设门。',
      gateWindowHint:'仅 fwd 生效：去程相对本组最小值相差 ≤ N ms 即准入。范围 1-500。组内无已收敛去程读数时自动回退 rtt 门。',
      algos:{auto:'auto（默认，粘滞+WFQ）',latency_strict:'latency_strict（严格最低去程）',latency_sticky:'latency_sticky（最低去程+粘滞）',min_rtt_strict:'min_rtt_strict（严格最低无拥塞地板）',min_rtt_adaptive:'min_rtt_adaptive（无拥塞地板+粘滞+WFQ）',roundtrip_strict:'roundtrip_strict（严格最低当前往返）'},
      fecs:{auto:'auto（所有健康后端轮转）',near:'near（去程时延 ≤ 数据路径 + 窗口）'},
      gates:{rtt:'rtt（内核往返地板，默认）',fwd:'fwd（本端去程排名键）'},
    },
    'zh-TW':{
      title:'排程設定',sub:'選路演算法、資格門與 FEC 同位元分發。熱更新生效，無需重新啟動。',labelAlgo:'選路演算法',labelFec:'FEC 同位元分發策略',labelWindow:'near 視窗 (ms)',labelGate:'候選資格門維度',labelGateWindow:'fwd 門視窗 (ms)',
      hint:'auto=去程穩定地板+服務時間（黏滯+WFQ）；latency_strict=嚴格最低去程地板；latency_sticky=最低去程地板+黏滯；min_rtt_strict=嚴格最低無壅塞地板；min_rtt_adaptive=無壅塞地板+黏滯+WFQ；roundtrip_strict=嚴格最低目前來回。',
      fecHint:'auto=所有健康後端輪轉（預設）；near=只投到去程單程延遲與資料路徑相差 ≤ 視窗的連線，抑制慢備援鏈路的同位元洩漏。',
      windowHint:'僅 near 生效：同位元只發給與資料路徑去程延遲相差 ≤ N ms 的連線。範圍 1-100。',
      gateHint:'rtt=依內核 min_rtt 來回地板設門（預設，方向盲）；fwd=依本端去程排名鍵設門，讓「去程最快但來回很慢」的極不對稱路徑也能准入——它慢的那一側是對端發送方向，由對端自己的門擋掉。兩端各自依發送方向設門。',
      gateWindowHint:'僅 fwd 生效：去程相對本組最小值相差 ≤ N ms 即准入。範圍 1-500。組內無已收斂去程讀數時自動回退 rtt 門。',
      algos:{auto:'auto（預設，黏滯+WFQ）',latency_strict:'latency_strict（嚴格最低去程）',latency_sticky:'latency_sticky（最低去程+黏滯）',min_rtt_strict:'min_rtt_strict（嚴格最低無壅塞地板）',min_rtt_adaptive:'min_rtt_adaptive（無壅塞地板+黏滯+WFQ）',roundtrip_strict:'roundtrip_strict（嚴格最低目前來回）'},
      fecs:{auto:'auto（所有健康後端輪轉）',near:'near（去程延遲 ≤ 資料路徑 + 視窗）'},
      gates:{rtt:'rtt（內核來回地板，預設）',fwd:'fwd（本端去程排名鍵）'},
    },
    'en':{
      title:'Scheduler settings',sub:'Routing algorithm, eligibility gate & FEC parity distribution. Hot-applied, no restart.',labelAlgo:'Routing algorithm',labelFec:'FEC parity strategy',labelWindow:'near window (ms)',labelGate:'Candidate eligibility gate',labelGateWindow:'fwd gate window (ms)',
      hint:'auto = stable forward floor + service time (sticky+WFQ); latency_strict = strictly lowest forward floor; latency_sticky = lowest forward floor + sticky; min_rtt_strict = strictly lowest congestion-free floor; min_rtt_adaptive = floor + sticky+WFQ; roundtrip_strict = strictly lowest current RTT.',
      fecHint:'auto = rotate across all healthy backends (default); near = only to backends within the window of the data path fwd, suppressing parity leakage to slower standby links.',
      windowHint:'Only for near: parity goes only to connections within N ms of the data path forward latency. Range 1-100.',
      gateHint:'rtt = gate on the kernel min_rtt round-trip floor (default, direction-blind); fwd = gate on this side\u2019s forward rank key, so an extremely asymmetric path that is fastest forward but slow round-trip still qualifies \u2014 its slow side is the peer\u2019s send direction, gated by the peer\u2019s own gate. Each side gates its own send direction.',
      gateWindowHint:'Only for fwd: a path qualifies when its forward latency is within N ms of the group minimum. Range 1-500. Falls back to the rtt gate when no forward reading has converged.',
      algos:{auto:'auto (default, sticky+WFQ)',latency_strict:'latency_strict (strict lowest forward)',latency_sticky:'latency_sticky (lowest forward + sticky)',min_rtt_strict:'min_rtt_strict (strict lowest congestion-free floor)',min_rtt_adaptive:'min_rtt_adaptive (floor + sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strict lowest current RTT)'},
      fecs:{auto:'auto (all healthy backends)',near:'near (fwd ≤ data path + window)'},
      gates:{rtt:'rtt (kernel round-trip floor, default)',fwd:'fwd (local forward rank key)'},
    },
    'de':{
      title:'Scheduler-Einstellungen',sub:'Routing-Algorithmus, Qualifikations-Tor & FEC-Parity-Verteilung. Heiß angewendet, kein Neustart.',labelAlgo:'Routing-Algorithmus',labelFec:'FEC-Parity-Strategie',labelWindow:'near-Fenster (ms)',labelGate:'Qualifikations-Tor',labelGateWindow:'fwd-Tor-Fenster (ms)',
      hint:'auto = stabiler Vorwärts-Boden + Servicezeit (Sticky+WFQ); latency_strict = strikt niedrigster Vorwärts-Boden; latency_sticky = niedrigster Vorwärts-Boden + Sticky; min_rtt_strict = strikt niedrigster staufreier Boden; min_rtt_adaptive = Boden + Sticky+WFQ; roundtrip_strict = strikt niedrigste aktuelle RTT.',
      fecHint:'auto = Rotation über alle gesunden Backends (Standard); near = nur zu Backends im Fenster der Datenpfad-Fwd, unterdrückt Parity-Leck auf langsamere Standby-Links.',
      windowHint:'Nur für near: Parity nur zu Verbindungen innerhalb N ms der Vorwärts-Latenz des Datenpfads. Bereich 1-100.',
      gateHint:'rtt = Tor an der Kernel-min_rtt-Rundlauf-Untergrenze (Standard, richtungsblind); fwd = Tor am eigenen Forward-Rangschlüssel, sodass ein extrem asymmetrischer Pfad, der forward am schnellsten ist aber langsam rundläuft, trotzdem zugelassen wird \u2013 seine langsame Seite ist die Senderrichtung des Peers, vom Tor des Peers selbst gehalten. Jede Seite torrt ihre eigene Senderrichtung.',
      gateWindowHint:'Nur für fwd: ein Pfad ist zugelassen, wenn seine Forward-Latenz innerhalb N ms der Gruppenniedrigste liegt. Bereich 1-500. Fällt auf das rtt-Tor zurück, wenn keine Forward-Messung konvergiert ist.',
      algos:{auto:'auto (Standard, Sticky+WFQ)',latency_strict:'latency_strict (strikt niedrigste Vorwärts-Latenz)',latency_sticky:'latency_sticky (niedrigste Vorwärts-Latenz + Sticky)',min_rtt_strict:'min_rtt_strict (strikt niedrigster staufreier Boden)',min_rtt_adaptive:'min_rtt_adaptive (Boden + Sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strikt niedrigste aktuelle RTT)'},
      fecs:{auto:'auto (alle gesunden Backends)',near:'near (fwd ≤ Datenpfad + Fenster)'},
      gates:{rtt:'rtt (Kernel-Rundlauf-Untergrenze, Standard)',fwd:'fwd (eigener Forward-Rangschlüssel)'},
    },
    'fr':{
      title:'Paramètres de l’ordonnanceur',sub:'Algorithme de routage, porte d’admission & distribution de parité FEC. Appliqué à chaud, sans redémarrage.',labelAlgo:'Algorithme de routage',labelFec:'Stratégie de parité FEC',labelWindow:'fenêtre near (ms)',labelGate:'Porte d’admission',labelGateWindow:'fenêtre fwd (ms)',
      hint:'auto = plancher avant stable + temps de service (sticky+WFQ) ; latency_strict = strictement le plancher avant le plus bas ; latency_sticky = plancher avant le plus bas + sticky ; min_rtt_strict = strictement le plancher sans congestion le plus bas ; min_rtt_adaptive = plancher + sticky+WFQ ; roundtrip_strict = strictement la RTT actuelle la plus basse.',
      fecHint:'auto = rotation sur tous les backends sains (défaut) ; near = uniquement aux backends dans la fenêtre de la fwd du chemin de données, supprime la fuite de parité vers les liens standby plus lents.',
      windowHint:'Uniquement pour near : parité envoyée aux connexions à N ms de la latence aller du chemin de données. Plage 1-100.',
      gateHint:'rtt = porte sur le plancher de min_rtt aller-retour du noyau (défaut, insensible à la direction) ; fwd = porte sur la clé de rang aller de ce côté, de sorte qu’un chemin très asymétrique, le plus rapide en aller mais lent en aller-retour, soit quand même admis — son côté lent est la direction d’envoi du pair, filtré par la porte du pair. Chaque côté filtre sa propre direction d’envoi.',
      gateWindowHint:'Uniquement pour fwd : un chemin est admis si sa latence aller est dans les N ms du minimum du groupe. Plage 1-500. Repli sur la porte rtt si aucune mesure aller n’est convergée.',
      algos:{auto:'auto (défaut, sticky+WFQ)',latency_strict:'latency_strict (strictement le plus bas aller)',latency_sticky:'latency_sticky (plus bas aller + sticky)',min_rtt_strict:'min_rtt_strict (strictement le plus bas plancher sans congestion)',min_rtt_adaptive:'min_rtt_adaptive (plancher + sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strictement la plus basse RTT actuelle)'},
      fecs:{auto:'auto (tous les backends sains)',near:'near (fwd ≤ chemin de données + fenêtre)'},
      gates:{rtt:'rtt (plancher aller-retour du noyau, défaut)',fwd:'fwd (clé de rang aller locale)'},
    },
    'ja':{
      title:'スケジューラ設定',sub:'選路アルゴリズム、資格ゲートと FEC パリティ配布。ホット適用、再起動不要。',labelAlgo:'選路アルゴリズム',labelFec:'FEC パリティ戦略',labelWindow:'near ウィンドウ (ms)',labelGate:'候補資格ゲートの次元',labelGateWindow:'fwd ゲート窓 (ms)',
      hint:'auto=安定した往路フロア＋サービス時間（スティッキー+WFQ）；latency_strict=厳密に最低の往路フロア；latency_sticky=最低の往路フロア＋スティッキー；min_rtt_strict=厳密に最低の輻輳なしフロア；min_rtt_adaptive=フロア＋スティッキー+WFQ；roundtrip_strict=厳密に最低の現在 RTT。',
      fecHint:'auto=全健全バックエンドでローテーション（デフォルト）；near=データパス fwd のウィンドウ内のみ、遅いスタンバイリンクへのパリティ漏れを抑制。',
      windowHint:'near のみ：データパスの往路遅延から N ms 以内の接続にのみパリティを送信。範囲 1-100。',
      gateHint:'rtt=カーネル min_rtt の往復フロアでゲート（デフォルト、方向盲）；fwd=本側の往路ランキングキーでゲートし、「往路は最速だが往復が遅い」極端に非対称なパスも准入できるようにする——その遅い側は対向側の送信方向であり、対向側自身のゲートが遮断する。両端がそれぞれ自らの送信方向でゲートする。',
      gateWindowHint:'fwd のみ：往路遅延がグループ最小値から N ms 以内なら准入。範囲 1-500。収束した往路読数がない場合は rtt ゲートに自動フォールバック。',
      algos:{auto:'auto（デフォルト、スティッキー+WFQ）',latency_strict:'latency_strict（厳密に最低の往路）',latency_sticky:'latency_sticky（最低往路＋スティッキー）',min_rtt_strict:'min_rtt_strict（厳密に最低の輻輳なしフロア）',min_rtt_adaptive:'min_rtt_adaptive（フロア＋スティッキー+WFQ）',roundtrip_strict:'roundtrip_strict（厳密に最低の現在RTT）'},
      fecs:{auto:'auto（全健全バックエンド）',near:'near（往路 ≤ データパス＋ウィンドウ）'},
      gates:{rtt:'rtt（カーネル往復フロア、デフォルト）',fwd:'fwd（本側往路ランキングキー）'},
    },
  };

  const css=document.createElement('style');
  css.textContent=`
    .rts-box{margin:12px 0 16px;padding:16px;border:1px solid var(--border);border-radius:12px;background:var(--card)}
    .rts-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px}.rts-head h3{margin:0 0 4px;font-size:16px}.rts-head p{margin:0;color:var(--sub);font-size:12px}
    .rts-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
    .rts-field{display:flex;flex-direction:column;gap:6px}.rts-field.wide{grid-column:1/-1}
    .rts-field label{font-size:12px;color:var(--sub);font-weight:600}
    .rts-field select,.rts-field input{width:100%;box-sizing:border-box;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 10px;font:inherit}
    .rts-help{font-size:11px;color:var(--sub);line-height:1.45}
    @media(max-width:760px){.rts-grid{grid-template-columns:1fr}}
  `;
  document.head.appendChild(css);

  const root=document.createElement('div');
  root.className='rts-box';
  root.innerHTML=`
    <div class="rts-head"><div><h3 data-rts-t="title"></h3><p data-rts-t="sub"></p></div></div>
    <div class="rts-grid">
      <div class="rts-field wide"><label data-rts-t="labelAlgo"></label>
        <select id="routing-algo">
          <option value="auto"></option><option value="latency_strict"></option><option value="latency_sticky"></option>
          <option value="min_rtt_strict"></option><option value="min_rtt_adaptive"></option><option value="roundtrip_strict"></option>
        </select>
        <div class="rts-help" data-rts-t="hint"></div>
      </div>
      <div class="rts-field"><label data-rts-t="labelFec"></label>
        <select id="fec-strategy"><option value="auto"></option><option value="near"></option></select>
        <div class="rts-help" data-rts-t="fecHint"></div>
      </div>
      <div class="rts-field" data-fec-near style="display:none"><label data-rts-t="labelWindow"></label>
        <input id="fec-near-window" type="number" min="1" max="100" step="1" inputmode="numeric">
        <div class="rts-help" data-rts-t="windowHint"></div>
      </div>
      <div class="rts-field"><label data-rts-t="labelGate"></label>
        <select id="sched-envelope"><option value="rtt"></option><option value="fwd"></option></select>
        <div class="rts-help" data-rts-t="gateHint"></div>
      </div>
      <div class="rts-field" data-sched-fwd style="display:none"><label data-rts-t="labelGateWindow"></label>
        <input id="sched-envelope-window" type="number" min="1" max="500" step="1" inputmode="numeric">
        <div class="rts-help" data-rts-t="gateWindowHint"></div>
      </div>
    </div>`;
  editor.parentNode.insertBefore(root,editor);

  const q=id=>document.getElementById(id);
  const algo=q('routing-algo'),fec=q('fec-strategy'),windowEl=q('fec-near-window');
  const gate=q('sched-envelope'),gateWindow=q('sched-envelope-window');
  if(!algo||!fec||!windowEl||!gate||!gateWindow)return;

  function lang(){const l=document.documentElement.lang||'en';return COPY[l]||COPY.en;}
  function translate(){
    const c=lang();
    root.querySelectorAll('[data-rts-t]').forEach(el=>{const k=el.dataset.rtsT;if(c[k]!=null)el.textContent=c[k];});
    Array.from(algo.options).forEach(o=>{o.textContent=c.algos[o.value]||o.value;});
    Array.from(fec.options).forEach(o=>{o.textContent=c.fecs[o.value]||o.value;});
    Array.from(gate.options).forEach(o=>{o.textContent=c.gates[o.value]||o.value;});
  }
  function parseEditor(){try{return JSON.parse(editor.value||'{}');}catch(_){return null;}}
  // optionValue 在 options 里线性找值：不能用 querySelector('option[value="…"]')，
  // JSON 里用户可控的值拼进属性选择器（含引号）会抛 SyntaxError 把整个加载炸掉。
  function optionValue(sel,v){
    if(v===undefined||v===null)return false;
    v=String(v);
    return Array.from(sel.options).some(function(o){return o.value===v;});
  }
  function updateNearVisibility(){root.querySelectorAll('[data-fec-near]').forEach(el=>{el.style.display=fec.value==='near'?'':'none';});}
  function updateGateVisibility(){root.querySelectorAll('[data-sched-fwd]').forEach(el=>{el.style.display=gate.value==='fwd'?'':'none';});}
  function fromEditor(){
    const cfg=parseEditor();if(!cfg)return false;
    // 五字段在 Config 顶层（全局，client 上行 / server 下行共用）。
    const av=cfg.routing_algo;
    if(av&&optionValue(algo,av))algo.value=String(av);
    const fv=cfg.fec_strategy;
    if(fv&&optionValue(fec,fv))fec.value=String(fv);
    windowEl.value=(cfg.fec_near_window_ms>=1&&cfg.fec_near_window_ms<=100)?String(cfg.fec_near_window_ms):'';
    const gv=cfg.sched_envelope;
    if(gv&&optionValue(gate,gv))gate.value=String(gv);
    gateWindow.value=(cfg.sched_envelope_ms>=1&&cfg.sched_envelope_ms<=500)?String(cfg.sched_envelope_ms):'';
    updateNearVisibility();updateGateVisibility();return true;
  }
  // syncDom=true：用户主动改下拉/输入框，DOM 值（合法）写入编辑器。
  // syncDom=false：保存前。只补空——编辑器里已有的值（无论是否合法）一律保留，
  // 让非法值原样送往后端校验并显示真实错误，而不是被静默强改成 auto/10。
  function toEditor(syncDom){
    const cfg=parseEditor();if(!cfg)return false;
    if(syncDom){
      cfg.routing_algo=algo.value||'auto';
      cfg.fec_strategy=fec.value||'auto';
      const w=parseInt(windowEl.value,10);
      cfg.fec_near_window_ms=(w>=1&&w<=100)?w:10;
      cfg.sched_envelope=gate.value||'rtt';
      const gw=parseInt(gateWindow.value,10);
      cfg.sched_envelope_ms=(gw>=1&&gw<=500)?gw:20;
    }else{
      if(!cfg.routing_algo)cfg.routing_algo=algo.value||'auto';
      if(!cfg.fec_strategy)cfg.fec_strategy=fec.value||'auto';
      if(cfg.fec_near_window_ms==null)cfg.fec_near_window_ms=10;
      if(!cfg.sched_envelope)cfg.sched_envelope=gate.value||'rtt';
      if(cfg.sched_envelope_ms==null)cfg.sched_envelope_ms=20;
    }
    editor.value=JSON.stringify(cfg,null,2);
    return true;
  }

  root.addEventListener('change',ev=>{
    if(ev.target===fec)updateNearVisibility();
    if(ev.target===gate)updateGateVisibility();
    if(ev.target===algo||ev.target===fec||ev.target===windowEl||ev.target===gate||ev.target===gateWindow)toEditor(true);
  });
  translate();fromEditor();

  const originalLoad=window.loadConfig;
  if(typeof originalLoad==='function')window.loadConfig=async function(){const r=await originalLoad.apply(this,arguments);fromEditor();return r;};
  const originalSave=window.saveConfig;
  if(typeof originalSave==='function')window.saveConfig=async function(){toEditor(false);const r=await originalSave.apply(this,arguments);if(arguments[0])setTimeout(fromEditor,0);return r;};
})();
