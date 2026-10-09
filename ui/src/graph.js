// Pure projection from the Python campaign format and append-only event records.
export const states = ['pending','running','passed','failed','blocked','inconclusive'];
export const colors = { pending:'#d9a441', running:'#4d91df', passed:'#2eae79', failed:'#da6262', blocked:'#8791a2', inconclusive:'#9096ab' };
export function project(campaign, events=[]) {
  if (!campaign || !Array.isArray(campaign.actions)) throw new Error('Invalid campaign');
  const actions = campaign.actions.map(a=>({...a,status:a.status||'pending',history:[]}));
  const lookup = new Map(actions.map(a=>[a.id,a]));
  if(lookup.size!==actions.length) throw new Error('Duplicate action ids');
  for (const action of actions){
    if(!states.includes(action.status)) throw new Error('Invalid state');
    for(const dep of [...(action.requires_all||[]),...(action.requires_any||[])]){
      if(!lookup.has(dep)) throw new Error('Unknown prerequisite: '+dep);
    }
  }
  for (const e of events){
    const action = lookup.get(e.action_id);
    if(!action || !states.includes(e.status)) throw new Error('Invalid event');
    action.status=e.status;
    action.history.push(e);
  }
  const levels = new Map();
  function depth(id, stack=new Set()) {
    if(levels.has(id)) return levels.get(id);
    if(stack.has(id)) throw new Error('Cycle in campaign');
    stack.add(id);
    const a=lookup.get(id);
    const deps=[...(a.requires_all||[]),...(a.requires_any||[])];
    const level=deps.length?1+Math.max(...deps.map(d=>depth(d,stack))):0;
    stack.delete(id); levels.set(id,level); return level;
  }
  for(const a of actions) depth(a.id);
  const rows = new Map();
  for(const a of actions){const level=levels.get(a.id);rows.set(level,[...(rows.get(level)||[]),a.id]);}
  const nodes=actions.map(a=>{
    const level=levels.get(a.id), index=rows.get(level).indexOf(a.id);
    return {id:a.id,position:{x:level*260,y:index*115},data:{label:a.title||a.id},
      style:`background:#1e2a3a;color:#f0f5fb;border:2px solid ${colors[a.status]};border-radius:10px;padding:13px;min-width:175px;font-size:12px;box-shadow:0 4px 20px #0003`};
  });
  const edges=[];
  for(const a of actions){
    for(const relation of ['requires_all','requires_any']){
      for(const dep of a[relation]||[]){edges.push({id:`${dep}→${a.id}:${relation}`,source:dep,target:a.id,
        label:relation==='requires_any'?'OR':'AND',animated:a.status==='running',
        style:{stroke:colors[lookup.get(dep).status],strokeWidth:2}});}
    }
  }
  return {nodes,edges,actions};
}
