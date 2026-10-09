<script>
  import { SvelteFlow, Controls, Background, BackgroundVariant } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';
  import { project, colors } from './graph.js';
  import demo from '../../examples/campaign-branching.json';
  let campaign=$state(demo);
  let events=$state([]);
  let selected=$state('inventory');
  let error=$state('');
  let graph=$derived(project(campaign,events));
  let nodes=$derived(graph.nodes);
  let edges=$derived(graph.edges);
  let action=$derived(graph.actions.find(a=>a.id===selected));
  let counts=$derived(Object.fromEntries(Object.keys(colors).map(k=>[k,graph.actions.filter(a=>a.status===k).length])));
  async function loadCampaign(event){
    try{const file=event.currentTarget.files?.[0]; if(!file)return;
      const data=JSON.parse(await file.text()); project(data,[]);campaign=data;events=[];selected=data.actions[0]?.id||'';error='';
    }catch(e){error=String(e.message||e);}
  }
  async function loadEvents(event){
    try{const file=event.currentTarget.files?.[0];if(!file)return;
      const records=(await file.text()).split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line));
      project(campaign,records); events=records;error='';
    }catch(e){error=String(e.message||e);}
  }
</script>
<svelte:head><title>Cyber Defense — Campaign</title></svelte:head>
<div class="shell">
  <header><div><small>CYBER DEFENSE / ASSESSMENT</small><h1>{campaign.name||'Investigation campaign'}</h1><p>Read-only investigation replay · outcomes describe checks, not confirmed compromises</p></div><div class="inputs"><label>Load campaign JSON <input aria-label="Campaign JSON" type="file" accept=".json,application/json" onchange={loadCampaign}></label><label>Load events JSONL <input aria-label="Event log JSONL" type="file" accept=".jsonl,.txt" onchange={loadEvents}></label></div></header>
  <section class="metrics">{#each Object.entries(counts) as [key,value]}<div class="metric"><span class="dot" style:background={colors[key]}></span><strong>{value}</strong><small>{key}</small></div>{/each}</section>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <main><section class="canvas" aria-label="Campaign dependency graph"><SvelteFlow {nodes} {edges} fitView nodesDraggable={false} nodesConnectable={false} elementsSelectable={false} colorMode="dark"><Controls/><Background variant={BackgroundVariant.Dots} gap={18} size={1}/></SvelteFlow></section>
    <aside><h2>Investigation steps</h2><div class="list">{#each graph.actions as item}<button class:chosen={selected===item.id} onclick={()=>selected=item.id}><span class="dot" style:background={colors[item.status]}></span><span>{item.title||item.id}<small>{item.status} · {item.id}</small></span></button>{/each}</div>
      {#if action}<section class="details"><h2>{action.title||action.id}</h2><p><strong>Status:</strong> <span style:color={colors[action.status]}>{action.status}</span></p><p><strong>All required:</strong> {(action.requires_all||[]).join(', ')||'none'}</p><p><strong>Any required:</strong> {(action.requires_any||[]).join(', ')||'none'}</p><h3>Evidence history</h3>{#if action.history.length}{#each action.history as item}<div class="evidence"><small>{item.timestamp||'No timestamp'} · {item.status}</small><p>{item.evidence||'No evidence reference'}</p></div>{/each}{:else}<p class="muted">No recorded attempts for this step.</p>{/if}</section>{/if}</aside></main>
  <footer>The UI does not execute assessments or change attack status. Record results with the Python campaign CLI and reload the JSONL file.</footer>
</div>
