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
      title:'调度设置',sub:'选路算法与 FEC parity 分发。热更生效，无需重启。',labelAlgo:'选路算法',labelFec:'FEC parity 分发策略',labelWindow:'near 窗口 (ms)',
      hint:'auto=去程稳定地板+服务时间（粘滞+WFQ）；*_strict=严格取最低时延路径（劣化即切换）；*_sticky/*_adaptive=带粘滞与 WFQ 字节公平分摊。',
      fecHint:'auto=所有健康后端轮转（默认）；near=只投到去程单程时延与数据路径相差 ≤ 窗口的连接，抑制慢备链路的 parity 泄漏。',
      windowHint:'仅 near 生效：parity 只发给与数据路径去程时延相差 ≤ N ms 的连接。范围 1-100。',
      algos:{auto:'auto（默认，粘滞+WFQ）',latency_strict:'latency_strict（严格最低去程）',latency_sticky:'latency_sticky（最低去程+粘滞）',min_rtt_strict:'min_rtt_strict（严格最低无拥塞地板）',min_rtt_adaptive:'min_rtt_adaptive（无拥塞地板+粘滞+WFQ）',roundtrip_strict:'roundtrip_strict（严格最低当前往返）'},
      fecs:{auto:'auto（所有健康后端轮转）',near:'near（去程时延 ≤ 数据路径 + 窗口）'},
    },
    'en':{
      title:'Scheduler settings',sub:'Routing algorithm & FEC parity distribution. Hot-applied, no restart.',labelAlgo:'Routing algorithm',labelFec:'FEC parity strategy',labelWindow:'near window (ms)',
      hint:'auto = stable forward floor + service time (sticky+WFQ); *_strict = strictly pick the lowest-latency path (switch on degradation); *_sticky/*_adaptive = with sticky hysteresis and WFQ byte fairness.',
      fecHint:'auto = rotate across all healthy backends (default); near = only to backends within the window of the data path fwd, suppressing parity leakage to slower standby links.',
      windowHint:'Only for near: parity goes only to connections within N ms of the data path forward latency. Range 1-100.',
      algos:{auto:'auto (default, sticky+WFQ)',latency_strict:'latency_strict (strict lowest forward)',latency_sticky:'latency_sticky (lowest forward + sticky)',min_rtt_strict:'min_rtt_strict (strict lowest congestion-free floor)',min_rtt_adaptive:'min_rtt_adaptive (floor + sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strict lowest current RTT)'},
      fecs:{auto:'auto (all healthy backends)',near:'near (fwd ≤ data path + window)'},
    },
    'de':{
      title:'Scheduler-Einstellungen',sub:'Routing-Algorithmus & FEC-Parity-Verteilung. Heiß angewendet, kein Neustart.',labelAlgo:'Routing-Algorithmus',labelFec:'FEC-Parity-Strategie',labelWindow:'near-Fenster (ms)',
      hint:'auto = stabiler Vorwärts-Boden + Servicezeit (Sticky+WFQ); *_strict = strikt niedrigste Latenz (Wechsel bei Verschlechterung); *_sticky/*_adaptive = mit Sticky und WFQ-Byte-Fairness.',
      fecHint:'auto = Rotation über alle gesunden Backends (Standard); near = nur zu Backends im Fenster der Datenpfad-Fwd, unterdrückt Parity-Leck auf langsamere Standby-Links.',
      windowHint:'Nur für near: Parity nur zu Verbindungen innerhalb N ms der Vorwärts-Latenz des Datenpfads. Bereich 1-100.',
      algos:{auto:'auto (Standard, Sticky+WFQ)',latency_strict:'latency_strict (strikt niedrigste Vorwärts-Latenz)',latency_sticky:'latency_sticky (niedrigste Vorwärts-Latenz + Sticky)',min_rtt_strict:'min_rtt_strict (strikt niedrigster staufreier Boden)',min_rtt_adaptive:'min_rtt_adaptive (Boden + Sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strikt niedrigste aktuelle RTT)'},
      fecs:{auto:'auto (alle gesunden Backends)',near:'near (fwd ≤ Datenpfad + Fenster)'},
    },
    'fr':{
      title:'Paramètres de l’ordonnanceur',sub:'Algorithme de routage & distribution de parité FEC. Appliqué à chaud, sans redémarrage.',labelAlgo:'Algorithme de routage',labelFec:'Stratégie de parité FEC',labelWindow:'fenêtre near (ms)',
      hint:'auto = plancher avant stable + temps de service (sticky+WFQ) ; *_strict = choisir strictement le chemin le moins latence (bascule en cas de dégradation) ; *_sticky/*_adaptive = avec hystérésis sticky et équité WFQ.',
      fecHint:'auto = rotation sur tous les backends sains (défaut) ; near = uniquement aux backends dans la fenêtre de la fwd du chemin de données, supprime la fuite de parité vers les liens standby plus lents.',
      windowHint:'Uniquement pour near : parité envoyée aux connexions à N ms de la latence aller du chemin de données. Plage 1-100.',
      algos:{auto:'auto (défaut, sticky+WFQ)',latency_strict:'latency_strict (strictement le plus bas aller)',latency_sticky:'latency_sticky (plus bas aller + sticky)',min_rtt_strict:'min_rtt_strict (strictement le plus bas plancher sans congestion)',min_rtt_adaptive:'min_rtt_adaptive (plancher + sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strictement la plus basse RTT actuelle)'},
      fecs:{auto:'auto (tous les backends sains)',near:'near (fwd ≤ chemin de données + fenêtre)'},
    },
    'ja':{
      title:'スケジューラ設定',sub:'選路アルゴリズムと FEC パリティ配布。ホット適用、再起動不要。',labelAlgo:'選路アルゴリズム',labelFec:'FEC パリティ戦略',labelWindow:'near ウィンドウ (ms)',
      hint:'auto=安定した往路フロア＋サービス時間（スティッキー+WFQ）；*_strict=厳密に最低遅延経路（劣化で即切替）；*_sticky/*_adaptive=スティッキーと WFQ バイト公平性付き。',
      fecHint:'auto=全健全バックエンドでローテーション（デフォルト）；near=データパス fwd のウィンドウ内のみ、遅いスタンバイリンクへのパリティ漏れを抑制。',
      windowHint:'near のみ：データパスの往路遅延から N ms 以内の接続にのみパリティを送信。範囲 1-100。',
      algos:{auto:'auto（デフォルト、スティッキー+WFQ）',latency_strict:'latency_strict（厳密に最低の往路）',latency_sticky:'latency_sticky（最低往路＋スティッキー）',min_rtt_strict:'min_rtt_strict（厳密に最低の輻輳なしフロア）',min_rtt_adaptive:'min_rtt_adaptive（フロア＋スティッキー+WFQ）',roundtrip_strict:'roundtrip_strict（厳密に最低の現在RTT）'},
      fecs:{auto:'auto（全健全バックエンド）',near:'near（往路 ≤ データパス＋ウィンドウ）'},
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
    </div>`;
  editor.parentNode.insertBefore(root,editor);

  const q=id=>document.getElementById(id);
  const algo=q('routing-algo'),fec=q('fec-strategy'),windowEl=q('fec-near-window');
  if(!algo||!fec||!windowEl)return;

  function lang(){const l=document.documentElement.lang||'en';return COPY[l]||COPY.en;}
  function translate(){
    const c=lang();
    root.querySelectorAll('[data-rts-t]').forEach(el=>{const k=el.dataset.rtsT;if(c[k]!=null)el.textContent=c[k];});
    Array.from(algo.options).forEach(o=>{o.textContent=c.algos[o.value]||o.value;});
    Array.from(fec.options).forEach(o=>{o.textContent=c.fecs[o.value]||o.value;});
  }
  function parseEditor(){try{return JSON.parse(editor.value||'{}');}catch(_){return null;}}
  function updateNearVisibility(){root.querySelectorAll('[data-fec-near]').forEach(el=>{el.style.display=fec.value==='near'?'':'none';});}
  function fromEditor(){
    const cfg=parseEditor();if(!cfg)return false;
    // 三字段在 Config 顶层（全局，client 上行 / server 下行共用）。
    const av=cfg.routing_algo;
    algo.value=(av&&algo.querySelector('option[value="'+av+'"]'))?av:'';
    const fv=cfg.fec_strategy;
    fec.value=(fv&&fec.querySelector('option[value="'+fv+'"]'))?fv:'';
    windowEl.value=(cfg.fec_near_window_ms>=1&&cfg.fec_near_window_ms<=100)?String(cfg.fec_near_window_ms):'';
    updateNearVisibility();return true;
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
    }else{
      if(!cfg.routing_algo)cfg.routing_algo=algo.value||'auto';
      if(!cfg.fec_strategy)cfg.fec_strategy=fec.value||'auto';
      if(cfg.fec_near_window_ms==null)cfg.fec_near_window_ms=10;
    }
    editor.value=JSON.stringify(cfg,null,2);
    return true;
  }

  root.addEventListener('change',ev=>{
    if(ev.target===fec)updateNearVisibility();
    if(ev.target===algo||ev.target===fec||ev.target===windowEl)toEditor(true);
  });
  translate();fromEditor();

  const originalLoad=window.loadConfig;
  if(typeof originalLoad==='function')window.loadConfig=async function(){const r=await originalLoad.apply(this,arguments);fromEditor();return r;};
  const originalSave=window.saveConfig;
  if(typeof originalSave==='function')window.saveConfig=async function(){toEditor(false);const r=await originalSave.apply(this,arguments);if(arguments[0])setTimeout(fromEditor,0);return r;};
})();
