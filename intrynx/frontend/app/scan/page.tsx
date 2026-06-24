"use client";

import React, { useState, useRef, useCallback, useEffect, useReducer } from "react";
import {
  Play, Square, AlertTriangle, Copy, Check, X,
  Crosshair, Cpu, Terminal, Zap, Shield, Activity,
  Eye, Network, Server, Globe, CheckCircle, XCircle,
  RotateCcw, Lock, ChevronRight, Radio,
  Target, Download, Wifi, ChevronDown, ChevronUp,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";
import {
  parseTargets, COMMON_RANGES, toApiTargets,
  type ParseResult,
} from "../../lib/target-parser";

/* ══ TYPES ══════════════════════════════════════════ */
type ScanTool    = "naabu"|"nmap"|"nuclei"|"openvas"|"netexec"|"impacket"|"testssl"|"eyewitness";
type StageStatus = "idle"|"running"|"done"|"error"|"skipped";
type ScanPhase   = "idle"|"running"|"complete"|"error";

interface StageState  { status: StageStatus; progress: number; message: string; }
interface FindingItem { id: string; title: string; severity: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"; host: string; source: string; timestamp: string; }
interface DiscoveredHost { ip: string; ports: number; hasWeb: boolean; hasAD: boolean; risk: "critical"|"high"|"medium"|"low"|"none"; hostname?: string; }
interface ScanState {
  phase: ScanPhase; scanId: string|null; startedAt: number|null; elapsed: number;
  stages: Record<ScanTool, StageState>; findings: FindingItem[];
  hosts: DiscoveredHost[]; logs: string[]; overallProgress: number;
}

/* ══ PRESETS ════════════════════════════════════════ */
interface ScanPreset {
  id: string; label: string; sublabel: string; icon: React.ReactNode;
  tools: ScanTool[]; eta: string; color: string; description: string; requiresCreds: boolean;
}
const PRESETS: ScanPreset[] = [
  { id:"recon",    label:"Recon",        sublabel:"Port sweep · minimal noise",       icon:<Crosshair size={13}/>, tools:["naabu"],                                                                      eta:"1–3m",   color:"var(--sev-low-color)",      description:"Fast SYN sweep, minimal noise, maximum speed.",              requiresCreds:false },
  { id:"web",      label:"Web Survey",   sublabel:"Apps + CVEs + TLS",                icon:<Globe size={13}/>,     tools:["naabu","nmap","nuclei","testssl","eyewitness"],                                eta:"5–15m",  color:"var(--sev-medium-color)",   description:"Ports → services → CVE templates → TLS → screenshots.",        requiresCreds:false },
  { id:"internal", label:"Internal",     sublabel:"LAN + SMB + services",             icon:<Network size={13}/>,   tools:["naabu","nmap","nuclei","netexec","testssl","eyewitness"],                      eta:"20–45m", color:"var(--sev-high-color)",     description:"Full internal sweep: SMB relay, null sessions, services.",    requiresCreds:false },
  { id:"ad",       label:"AD Assess",    sublabel:"Kerberos + LDAP",                  icon:<Shield size={13}/>,    tools:["naabu","nmap","netexec","impacket","testssl"],                                 eta:"20–40m", color:"var(--sev-critical-color)", description:"AD: Kerberoasting, AS-REP roasting, LDAP anon bind, SMBv1.", requiresCreds:true  },
  { id:"full",     label:"Full VAPT",    sublabel:"All 8 tools · deep scan",          icon:<Zap size={13}/>,       tools:["naabu","nmap","nuclei","openvas","netexec","impacket","testssl","eyewitness"],  eta:"60–180m",color:"var(--sev-critical-color)", description:"Complete assessment: all modules chained, deep authenticated scan.", requiresCreds:true  },
  { id:"custom",   label:"Custom",       sublabel:"Expert mode · select tools",       icon:<Activity size={13}/>,  tools:[],                                                                              eta:"—",      color:"var(--text-secondary)",    description:"Manually select tools and tune every parameter.",             requiresCreds:false },
];

const ALL_TOOLS: ScanTool[] = ["naabu","nmap","nuclei","openvas","netexec","impacket","testssl","eyewitness"];
const TOOL_META: Record<ScanTool,{label:string;desc:string;icon:React.ReactNode;color:string}> = {
  naabu:     {label:"Port Scanner",    desc:"SYN port sweep",               icon:<Crosshair size={12}/>,     color:"var(--sev-low-color)"     },
  nmap:      {label:"Service Probe",   desc:"Service + OS fingerprint",     icon:<Server size={12}/>,        color:"var(--accent)"            },
  nuclei:    {label:"CVE Engine",      desc:"CVE + misconfiguration",       icon:<AlertTriangle size={12}/>, color:"var(--sev-high-color)"    },
  openvas:   {label:"Vuln Scanner",    desc:"Authenticated CVE scan",       icon:<Shield size={12}/>,        color:"var(--sev-critical-color)"},
  netexec:   {label:"SMB Auditor",     desc:"SMBv1, signing, null sessions",icon:<Network size={12}/>,       color:"#9C6FDE"                  },
  impacket:  {label:"Kerberos Probe",  desc:"Kerberoast, AS-REP, LDAP",    icon:<Cpu size={12}/>,           color:"var(--sev-critical-color)"},
  testssl:   {label:"TLS Analyzer",    desc:"TLS ciphers, cert, HSTS",     icon:<Lock size={12}/>,          color:"var(--sev-medium-color)"  },
  eyewitness:{label:"Web Capture",     desc:"Web screenshots + panels",    icon:<Eye size={12}/>,           color:"var(--accent)"            },
};

const STEALTH_OPTS = [
  {id:1, label:"Ghost",     short:"G", color:"var(--sev-low-color)",      rate:50,   timing:"T1"},
  {id:3, label:"Cautious",  short:"C", color:"var(--accent)",             rate:300,  timing:"T2"},
  {id:5, label:"Balanced",  short:"B", color:"var(--sev-medium-color)",   rate:1000, timing:"T3"},
  {id:7, label:"Aggressive",short:"A", color:"var(--sev-high-color)",     rate:3000, timing:"T4"},
  {id:9, label:"Maximum",   short:"M", color:"var(--sev-critical-color)", rate:5000, timing:"T5"},
];

/* ══ REDUCER ════════════════════════════════════════ */
const EMPTY_STAGES = Object.fromEntries(ALL_TOOLS.map(t=>[t,{status:"idle" as StageStatus,progress:0,message:"Waiting"}])) as Record<ScanTool,StageState>;
type Action =
  |{type:"START";scanId:string}|{type:"LOG";line:string}
  |{type:"STAGE_UPDATE";tool:ScanTool;partial:Partial<StageState>}
  |{type:"FINDING";finding:FindingItem}|{type:"HOST";host:DiscoveredHost}
  |{type:"PROGRESS";overall:number}|{type:"COMPLETE"}
  |{type:"ERROR";msg:string}|{type:"RESET"}|{type:"TICK"};

function scanReducer(state:ScanState,action:Action):ScanState {
  switch(action.type){
    case"START":    return{...state,phase:"running",scanId:action.scanId,startedAt:Date.now(),elapsed:0,findings:[],hosts:[],logs:[],stages:{...EMPTY_STAGES}};
    case"LOG":      return{...state,logs:[...state.logs.slice(-500),action.line]};
    case"STAGE_UPDATE": return{...state,stages:{...state.stages,[action.tool]:{...state.stages[action.tool],...action.partial}}};
    case"FINDING":  return{...state,findings:[action.finding,...state.findings]};
    case"HOST":     return{...state,hosts:[...state.hosts.filter(h=>h.ip!==action.host.ip),action.host]};
    case"PROGRESS": return{...state,overallProgress:action.overall};
    case"COMPLETE": return{...state,phase:"complete",overallProgress:100};
    case"ERROR":    return{...state,phase:"error",logs:[...state.logs,`[ERROR] ${action.msg}`]};
    case"TICK":     return state.startedAt?{...state,elapsed:Math.floor((Date.now()-state.startedAt)/1000)}:state;
    case"RESET":    return{phase:"idle",scanId:null,startedAt:null,elapsed:0,stages:{...EMPTY_STAGES},findings:[],hosts:[],logs:[],overallProgress:0};
    default: return state;
  }
}

/* ══ HELPERS ════════════════════════════════════════ */
const SEV:Record<string,{color:string;bg:string}> = {
  CRITICAL:{color:"var(--sev-critical-color)",bg:"var(--sev-critical-bg)"},
  HIGH:    {color:"var(--sev-high-color)",    bg:"var(--sev-high-bg)"    },
  MEDIUM:  {color:"var(--sev-medium-color)",  bg:"var(--sev-medium-bg)"  },
  LOW:     {color:"var(--sev-low-color)",     bg:"var(--sev-low-bg)"     },
  INFO:    {color:"var(--text-muted)",        bg:"rgba(136,146,164,0.08)"},
};
function fmtTime(s:number){
  if(s<60)return`${s}s`;
  if(s<3600)return`${Math.floor(s/60)}m ${s%60}s`;
  return`${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
}
function CopyBtn({text}:{text:string}){
  const[c,setC]=useState(false);
  return(
    <button onClick={()=>{navigator.clipboard.writeText(text);setC(true);setTimeout(()=>setC(false),2000);}}
      style={{background:"none",border:"none",cursor:"pointer",padding:"3px 6px",borderRadius:4,color:c?"var(--accent)":"var(--text-muted)",transition:"color 0.15s"}}>
      {c?<Check size={11}/>:<Copy size={11}/>}
    </button>
  );
}

/* ══ PIPELINE NODE ══════════════════════════════════ */
function PipeNode({tool,status,progress,isLast}:{tool:ScanTool;status:StageStatus;progress:number;isLast:boolean}){
  const m=TOOL_META[tool];
  const isRun=status==="running";
  const isDone=status==="done";
  const isErr=status==="error";
  const isIdle=status==="idle"||status==="skipped";
  const col=isDone?"var(--accent)":isErr?"var(--sev-critical-color)":isRun?m.color:"var(--border-strong)";

  return(
    <div style={{display:"flex",alignItems:"center",flex:1,minWidth:0}}>
      <div style={{
        flex:1,display:"flex",flexDirection:"column",alignItems:"center",gap:5,
        padding:"12px 8px 10px",
        background:isRun?`color-mix(in srgb,${m.color} 6%,var(--bg-surface))`:isDone?"rgba(0,200,232,0.04)":"transparent",
        border:`0.5px solid ${isRun?m.color:isDone?"rgba(0,200,232,0.15)":isErr?"rgba(255,77,77,0.2)":"var(--border-subtle)"}`,
        borderRadius:10,
        transition:"all 0.3s ease",
        boxShadow:isRun?`0 0 20px color-mix(in srgb,${m.color} 12%,transparent)`:isDone?"0 0 8px rgba(0,200,232,0.08)":"none",
        position:"relative",overflow:"hidden",
      }}>
        {/* shimmer when running */}
        {isRun&&<div style={{position:"absolute",top:0,left:0,right:0,height:"100%",background:"linear-gradient(90deg,transparent,rgba(255,255,255,0.02),transparent)",backgroundSize:"200% 100%",animation:"shimmer 2s infinite"}}/>}

        {/* Icon ring */}
        <div style={{
          width:36,height:36,borderRadius:"50%",
          border:`1.5px solid ${col}`,
          background:isRun?`color-mix(in srgb,${m.color} 10%,transparent)`:isDone?"rgba(0,200,232,0.08)":"var(--bg-surface)",
          display:"flex",alignItems:"center",justifyContent:"center",
          position:"relative",flexShrink:0,
          boxShadow:isRun?`0 0 12px color-mix(in srgb,${m.color} 20%,transparent)`:isDone?"0 0 6px rgba(0,200,232,0.15)":"none",
          transition:"all 0.3s",
        }}>
          {isRun&&<div style={{position:"absolute",inset:-4,borderRadius:"50%",border:"1.5px solid transparent",borderTopColor:m.color,animation:"spin 0.9s linear infinite",opacity:0.7}}/>}
          {isDone?<Check size={14} color="var(--accent)"/>:isErr?<X size={14} color="var(--sev-critical-color)"/>:<div style={{color:col,opacity:isIdle?0.25:1}}>{m.icon}</div>}
        </div>

        <span style={{
          fontFamily:"'JetBrains Mono',monospace",fontSize:9,fontWeight:isRun?700:400,
          color:col,letterSpacing:0.5,whiteSpace:"nowrap",
        }}>{m.label}</span>

        {/* Progress bar */}
        <div style={{width:"80%",height:2,background:"rgba(255,255,255,0.06)",borderRadius:1,overflow:"hidden"}}>
          <div style={{height:"100%",width:`${progress}%`,background:col,borderRadius:1,transition:"width 0.5s ease"}}/>
        </div>

        {isRun&&(
          <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:m.color,opacity:0.8}}>{progress}%</span>
        )}
      </div>

      {!isLast&&(
        <div style={{flexShrink:0,display:"flex",alignItems:"center",padding:"0 3px"}}>
          <div style={{width:14,height:1,background:isDone?"rgba(0,200,232,0.20)":"var(--border-subtle)"}}/>
          <div style={{
            width:5,height:5,
            borderTop:`1px solid ${isDone?"rgba(0,200,232,0.25)":"var(--border-subtle)"}`,
            borderRight:`1px solid ${isDone?"rgba(0,200,232,0.25)":"var(--border-subtle)"}`,
            transform:"rotate(45deg)",marginLeft:-4,
          }}/>
        </div>
      )}
    </div>
  );
}

/* ══ MAIN PAGE ══════════════════════════════════════ */
export default function ScanPage(){
  const{success,error:toastError,info,warning}=useToast();

  const[rawTargets,setRawTargets]=useState("");
  const[exclusions,setExclusions]=useState("");
  const[showExclusions,setShowExclusions]=useState(false);
  const[selectedPreset,setSelectedPreset]=useState("internal");
  const[customTools,setCustomTools]=useState<ScanTool[]>([...ALL_TOOLS]);
  const[stealth,setStealth]=useState(STEALTH_OPTS[2]);
  const[showCreds,setShowCreds]=useState(false);
  const[creds,setCreds]=useState({domain:"",username:"",password:"",dcIp:""});
  const[createFindings,setCreateFindings]=useState(true);
  const[parseResult,setParseResult]=useState<ParseResult|null>(null);
  const[activeTab,setActiveTab]=useState<"findings"|"hosts"|"terminal">("findings");
  const[profileOpen,setProfileOpen]=useState(false);
  const[profilePos,setProfilePos]=useState({top:0,left:0,width:0});
  const profileBtnRef=useRef<HTMLButtonElement>(null);
  const profileDropRef=useRef<HTMLDivElement>(null);
  const parseTimer=useRef<ReturnType<typeof setTimeout>|null>(null);

  const[scan,dispatch]=useReducer(scanReducer,{
    phase:"idle",scanId:null,startedAt:null,elapsed:0,
    stages:{...EMPTY_STAGES},findings:[],hosts:[],logs:[],overallProgress:0,
  });

  const abortRef=useRef<AbortController|null>(null);
  const logRef=useRef<HTMLDivElement>(null);
  const tickRef=useRef<ReturnType<typeof setInterval>|null>(null);

  useEffect(()=>{
    if(logRef.current)logRef.current.scrollTop=logRef.current.scrollHeight;
  },[scan.logs]);
  useEffect(()=>{
    if(scan.phase==="running"){tickRef.current=setInterval(()=>dispatch({type:"TICK"}),1000);}
    else{if(tickRef.current)clearInterval(tickRef.current);}
    return()=>{if(tickRef.current)clearInterval(tickRef.current);};
  },[scan.phase]);
  useEffect(()=>{
    function onDown(e:MouseEvent){
      const t=e.target as Node;
      if(profileBtnRef.current&&!profileBtnRef.current.contains(t)&&profileDropRef.current&&!profileDropRef.current.contains(t))
        setProfileOpen(false);
    }
    document.addEventListener("mousedown",onDown);
    return()=>document.removeEventListener("mousedown",onDown);
  },[]);

  const openProfile=useCallback(()=>{
    if(!profileOpen&&profileBtnRef.current){
      const r=profileBtnRef.current.getBoundingClientRect();
      setProfilePos({top:r.bottom+6,left:r.left,width:r.width});
    }
    setProfileOpen(p=>!p);
  },[profileOpen]);

  useEffect(()=>{
    if(parseTimer.current)clearTimeout(parseTimer.current);
    parseTimer.current=setTimeout(()=>{
      if(!rawTargets.trim()){setParseResult(null);return;}
      setParseResult(parseTargets(rawTargets,exclusions.split(/[\n,;]+/).map(s=>s.trim()).filter(Boolean)));
    },300);
    return()=>{if(parseTimer.current)clearTimeout(parseTimer.current);};
  },[rawTargets,exclusions]);

  const preset=PRESETS.find(p=>p.id===selectedPreset)??PRESETS[2];
  const activeTools=preset.id==="custom"?customTools:preset.tools;

  const handleSseEvent=useCallback((ev:Record<string,unknown>)=>{
    const ts=new Date().toISOString().slice(11,19);
    switch(ev.type){
      case"pipeline_started": dispatch({type:"LOG",line:`[${ts}] Pipeline ${ev.scanId} started`}); break;
      case"progress":{
        dispatch({type:"PROGRESS",overall:ev.overallProgress as number});
        const stages=ev.stages as Record<ScanTool,StageState>;
        for(const[tool,s]of Object.entries(stages)){
          dispatch({type:"STAGE_UPDATE",tool:tool as ScanTool,partial:s});
          if(s.status==="running")dispatch({type:"LOG",line:`[${ts}] ${TOOL_META[tool as ScanTool]?.label}: ${s.message}`});
        }
        break;
      }
      case"finding":{
        const f=ev.finding as FindingItem;
        dispatch({type:"FINDING",finding:{...f,timestamp:new Date().toISOString()}});
        dispatch({type:"LOG",line:`[${ts}] ◆ [${f.severity}] ${f.title} — ${f.host}`});
        break;
      }
      case"host_discovered":{
        const h=ev.host as DiscoveredHost;
        dispatch({type:"HOST",host:h});
        dispatch({type:"LOG",line:`[${ts}] ↑ ${h.ip} · ${h.ports} ports`});
        break;
      }
      case"pipeline_complete":
        dispatch({type:"COMPLETE"});
        dispatch({type:"LOG",line:`[${ts}] ✓ Complete · ${scan.findings.length} findings · ${scan.hosts.length} hosts`});
        success("Scan complete",`${scan.findings.length} findings across ${scan.hosts.length} hosts`);
        break;
      case"error": dispatch({type:"ERROR",msg:String(ev.error)}); break;
    }
  },[scan.findings.length,scan.hosts.length,success]);

  const startScan=useCallback(async()=>{
    if(!parseResult||parseResult.valid.length===0){toastError("No targets","Add at least one valid IP, CIDR, or hostname.");return;}
    if(parseResult.hasPublicIPs)warning("Public IPs","Ensure you have written authorization.");
    if(preset.requiresCreds&&!creds.username)info("Credentials recommended",`${preset.label} works best with domain credentials.`);
    const targets=toApiTargets(parseResult);
    const scanId=`scan-${Date.now()}`;
    dispatch({type:"START",scanId});
    dispatch({type:"LOG",line:`[${new Date().toISOString().slice(11,19)}] Launching ${preset.label} · ${targets.length} target(s) · stealth:${stealth.label} · ${activeTools.length} modules`});
    abortRef.current=new AbortController();
    try{
      const res=await fetch("/api/scan/pipeline",{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({targets,profile:preset.id==="full"?"deep":"standard",tools:activeTools,credentials:showCreds&&creds.username?creds:{},createFindings,stealthLevel:stealth.id}),
        signal:abortRef.current.signal,
      });
      if(!res.ok||!res.body){dispatch({type:"ERROR",msg:"Failed to start pipeline"});toastError("Scan failed","Could not start pipeline.");return;}
      const reader=res.body.getReader();const decoder=new TextDecoder();let buffer="";
      while(true){
        const{done,value}=await reader.read();if(done)break;
        buffer+=decoder.decode(value,{stream:true});
        const lines=buffer.split("\n");buffer=lines.pop()??"";
        for(const line of lines){
          if(!line.startsWith("data: "))continue;
          try{handleSseEvent(JSON.parse(line.slice(6)) as Record<string,unknown>);}catch{}
        }
      }
    }catch(e:unknown){
      if(e instanceof Error&&e.name!=="AbortError"){dispatch({type:"ERROR",msg:String(e)});toastError("Scan error",String(e).slice(0,100));}
      else if(e instanceof Error&&e.name==="AbortError"){dispatch({type:"LOG",line:`[${new Date().toISOString().slice(11,19)}] Aborted by user`});dispatch({type:"COMPLETE"});}
    }
  },[parseResult,preset,activeTools,creds,showCreds,createFindings,stealth,toastError,info,warning,handleSseEvent]);

  const running=scan.phase==="running";
  const hasRun=scan.phase!=="idle";
  const isDone=scan.phase==="complete"||scan.phase==="error";
  const canLaunch=!!parseResult&&parseResult.valid.length>0;

  const sevCounts={
    CRITICAL:scan.findings.filter(f=>f.severity==="CRITICAL").length,
    HIGH:    scan.findings.filter(f=>f.severity==="HIGH").length,
    MEDIUM:  scan.findings.filter(f=>f.severity==="MEDIUM").length,
    LOW:     scan.findings.filter(f=>f.severity==="LOW").length,
  };

  /* ── RENDER ─────────────────────────────────────── */
  return(
    <PageShell
      title="Scan Engine"
      subtitle={running?`${scan.overallProgress}%  ·  ${fmtTime(scan.elapsed)}  ·  ${preset.label}`:"Offensive Vulnerability Pipeline"}
      statusItems={hasRun?[
        {label:"HOSTS",    value:String(scan.hosts.length),  color:"var(--accent)"},
        {label:"CRITICAL", value:String(sevCounts.CRITICAL), color:sevCounts.CRITICAL>0?"var(--sev-critical-color)":"var(--text-muted)"},
        {label:"HIGH",     value:String(sevCounts.HIGH),     color:sevCounts.HIGH>0?"var(--sev-high-color)":"var(--text-muted)"},
        {label:"ELAPSED",  value:fmtTime(scan.elapsed),      color:"var(--text-secondary)"},
      ]:[]}
    >
      <style>{`
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes ring-pulse{0%,100%{opacity:0.05;transform:scale(1)}50%{opacity:0.1;transform:scale(1.03)}}
        @keyframes radar-sweep{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
        @keyframes scanline{0%{transform:translateY(-100%)}100%{transform:translateY(100vh)}}
        @keyframes blink{0%,49%{opacity:1}50%,100%{opacity:0}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
        @keyframes glow-pulse{0%,100%{box-shadow:0 0 20px var(--accent-glow)}50%{box-shadow:0 0 40px var(--accent-glow),0 0 60px var(--accent-glow)}}
        @keyframes dropdownIn{from{opacity:0;transform:translateY(-8px) scale(0.97)}to{opacity:1;transform:translateY(0) scale(1)}}
        .scan-finding-row{animation:fadeIn 0.25s ease both}
      `}</style>

      <div style={{display:"grid",gridTemplateColumns:"260px 1fr",gap:14,height:"calc(100vh - 108px)",overflow:"hidden"}}>

        {/* ════════════════════════════════════
            LEFT — CONFIG PANEL
        ════════════════════════════════════ */}
        <div style={{
          display:"flex",flexDirection:"column",
          background:"var(--bg-panel)",
          border:"0.5px solid var(--border-subtle)",
          borderRadius:14,overflow:"hidden",
        }}>

          {/* Header */}
          <div style={{
            padding:"14px 16px 12px",
            borderBottom:"0.5px solid var(--border-subtle)",
            background:"linear-gradient(180deg,rgba(0,200,232,0.03) 0%,transparent 100%)",
            flexShrink:0,
          }}>
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              <div style={{
                width:30,height:30,borderRadius:8,
                background:"var(--accent-ghost)",border:"0.5px solid var(--border-accent)",
                display:"flex",alignItems:"center",justifyContent:"center",
              }}>
                <Target size={14} color="var(--accent)"/>
              </div>
              <div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,fontWeight:700,color:"var(--text-primary)",letterSpacing:1.5}}>SCAN CONFIG</div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"var(--text-muted)",marginTop:2}}>
                  {preset.label} · {stealth.label} · {activeTools.length} tools
                </div>
              </div>
              {canLaunch&&!running&&(
                <div style={{
                  marginLeft:"auto",width:7,height:7,borderRadius:"50%",
                  background:"var(--accent)",boxShadow:"0 0 8px var(--accent)",
                  animation:"pulse 2s ease-in-out infinite",
                }}/>
              )}
            </div>
          </div>

          <div style={{flex:1,overflowY:"auto",display:"flex",flexDirection:"column"}}>

            {/* TARGETS */}
            <div style={{padding:"12px 14px",borderBottom:"0.5px solid var(--border-subtle)"}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:7}}>
                <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,fontWeight:700,color:"var(--text-faint)",letterSpacing:1.4,textTransform:"uppercase"}}>Targets</span>
                {parseResult&&(
                  <span style={{
                    fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                    color:parseResult.invalid.length>0?"var(--sev-high-color)":"var(--accent)",
                    background:parseResult.invalid.length>0?"var(--sev-high-bg)":"var(--accent-ghost)",
                    border:`0.5px solid ${parseResult.invalid.length>0?"rgba(255,160,0,0.3)":"rgba(0,200,232,0.30)"}`,
                    borderRadius:8,padding:"2px 7px",
                  }}>{parseResult.valid.length} target{parseResult.valid.length!==1?"s":""} · {parseResult.totalHosts.toLocaleString()} hosts</span>
                )}
              </div>

              <div style={{position:"relative"}}>
                <textarea value={rawTargets} onChange={e=>setRawTargets(e.target.value)}
                  placeholder={"10.0.0.0/24\n192.168.1.1-50\ndc01.corp.local\n\nPaste any scope — IPs extracted auto"}
                  rows={5} style={{
                    width:"100%",boxSizing:"border-box",
                    background:"var(--bg-surface)",
                    border:"0.5px solid var(--border-default)",
                    borderRadius:8,padding:"9px 30px 9px 10px",
                    fontFamily:"'JetBrains Mono',monospace",fontSize:10,
                    color:"var(--text-primary)",resize:"none",outline:"none",lineHeight:1.7,
                    transition:"border-color 0.15s,box-shadow 0.15s",
                  }}
                  onFocus={e=>{e.target.style.borderColor="var(--accent)";e.target.style.boxShadow="0 0 0 3px var(--accent-ghost)";}}
                  onBlur={e=>{e.target.style.borderColor="var(--border-default)";e.target.style.boxShadow="none";}}
                />
                {rawTargets&&(
                  <button onClick={()=>setRawTargets("")}
                    style={{position:"absolute",top:7,right:7,background:"var(--bg-hover)",border:"none",borderRadius:4,cursor:"pointer",padding:"2px 4px",color:"var(--text-muted)"}}
                    onMouseEnter={e=>(e.currentTarget.style.color="var(--sev-critical-color)")}
                    onMouseLeave={e=>(e.currentTarget.style.color="var(--text-muted)")}
                  ><X size={10}/></button>
                )}
              </div>

              {parseResult?.hasPublicIPs&&(
                <div style={{marginTop:5,display:"flex",alignItems:"center",gap:5,padding:"5px 8px",background:"rgba(255,77,77,0.06)",border:"0.5px solid rgba(255,77,77,0.2)",borderRadius:5}}>
                  <AlertTriangle size={9} color="var(--sev-critical-color)"/>
                  <span style={{fontFamily:"'Inter',sans-serif",fontSize:10,color:"var(--sev-critical-color)"}}>Public IPs — written authorization required</span>
                </div>
              )}

              <div style={{display:"flex",flexWrap:"wrap",gap:3,marginTop:7}}>
                {COMMON_RANGES.map(r=>(
                  <button key={r.cidr} onClick={()=>setRawTargets(p=>p?`${p}\n${r.cidr}`:r.cidr)}
                    style={{padding:"2px 6px",borderRadius:4,border:"0.5px solid var(--border-subtle)",background:"var(--bg-surface)",cursor:"pointer",fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"var(--text-muted)",transition:"all 0.12s"}}
                    onMouseEnter={e=>{e.currentTarget.style.borderColor="var(--accent)";e.currentTarget.style.color="var(--accent)";e.currentTarget.style.background="var(--accent-ghost)";}}
                    onMouseLeave={e=>{e.currentTarget.style.borderColor="var(--border-subtle)";e.currentTarget.style.color="var(--text-muted)";e.currentTarget.style.background="var(--bg-surface)";}}
                  >{r.label}</button>
                ))}
              </div>

              <button onClick={()=>setShowExclusions(p=>!p)}
                style={{marginTop:6,display:"flex",alignItems:"center",gap:3,background:"none",border:"none",cursor:"pointer",color:"var(--text-muted)",fontFamily:"'Inter',sans-serif",fontSize:9,padding:0,transition:"color 0.12s"}}
                onMouseEnter={e=>(e.currentTarget.style.color="var(--text-secondary)")}
                onMouseLeave={e=>(e.currentTarget.style.color="var(--text-muted)")}
              >
                {showExclusions?<ChevronUp size={9}/>:<ChevronDown size={9}/>} Exclusions
              </button>
              {showExclusions&&(
                <textarea value={exclusions} onChange={e=>setExclusions(e.target.value)}
                  placeholder={"10.0.0.1\n192.168.1.0/24"} rows={2}
                  style={{marginTop:4,width:"100%",boxSizing:"border-box",background:"rgba(255,77,77,0.04)",border:"0.5px solid rgba(255,77,77,0.2)",borderRadius:6,padding:"6px 8px",fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"var(--sev-critical-color)",resize:"none",outline:"none",lineHeight:1.6}}
                />
              )}
            </div>

            {/* SCAN PROFILE DROPDOWN */}
            {/* ── SCAN PROFILE ── */}
            <div style={{padding:"12px 14px",borderBottom:"0.5px solid var(--border-subtle)"}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,fontWeight:700,color:"var(--text-faint)",letterSpacing:1.4,textTransform:"uppercase"}}>Scan Profile</span>
                <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"var(--text-muted)"}}>{activeTools.length} tools</span>
              </div>

              {/* Trigger button */}
              <button ref={profileBtnRef} onClick={openProfile} style={{
                width:"100%",display:"flex",alignItems:"center",gap:10,
                padding:"10px 12px",cursor:"pointer",
                background:profileOpen
                  ?`color-mix(in srgb,${preset.color} 12%,var(--bg-surface))`
                  :"var(--bg-surface)",
                border:`0.5px solid ${profileOpen?preset.color:"var(--border-default)"}`,
                borderRadius:10,transition:"all 0.15s",
                boxShadow:profileOpen?`0 0 0 3px color-mix(in srgb,${preset.color} 12%,transparent),0 4px 16px rgba(0,0,0,0.3)`:"none",
              }}
                onMouseEnter={e=>{if(!profileOpen){e.currentTarget.style.borderColor="var(--border-strong)";e.currentTarget.style.background="var(--bg-hover)";}}}
                onMouseLeave={e=>{if(!profileOpen){e.currentTarget.style.borderColor="var(--border-default)";e.currentTarget.style.background="var(--bg-surface)";}}}
              >
                {/* Icon tile */}
                <div style={{
                  width:32,height:32,borderRadius:8,flexShrink:0,
                  background:`color-mix(in srgb,${preset.color} 14%,var(--bg-panel))`,
                  border:`1px solid color-mix(in srgb,${preset.color} 28%,transparent)`,
                  display:"flex",alignItems:"center",justifyContent:"center",
                  color:preset.color,
                  boxShadow:`0 0 12px color-mix(in srgb,${preset.color} 18%,transparent)`,
                  transition:"all 0.15s",
                }}>{preset.icon}</div>

                {/* Labels */}
                <div style={{flex:1,textAlign:"left",minWidth:0}}>
                  <div style={{display:"flex",alignItems:"center",gap:5,marginBottom:2}}>
                    <span style={{fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:600,color:"var(--text-primary)",lineHeight:1}}>{preset.label}</span>
                    {preset.requiresCreds&&(
                      <span style={{display:"inline-flex",alignItems:"center",gap:2,fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:"var(--sev-medium-color)",background:"var(--sev-medium-bg)",border:"0.5px solid var(--sev-medium-color)",borderRadius:3,padding:"1px 4px",fontWeight:700,lineHeight:1.4}}>
                        <Lock size={6}/>CREDS
                      </span>
                    )}
                  </div>
                  <div style={{fontFamily:"'Inter',sans-serif",fontSize:9,color:"var(--text-muted)"}}>{preset.sublabel}</div>
                </div>

                {/* Right: ETA + chevron */}
                <div style={{display:"flex",alignItems:"center",gap:6,flexShrink:0}}>
                  <span style={{
                    fontFamily:"'JetBrains Mono',monospace",fontSize:9,fontWeight:600,
                    color:preset.color,
                    background:`color-mix(in srgb,${preset.color} 10%,transparent)`,
                    border:`0.5px solid color-mix(in srgb,${preset.color} 25%,transparent)`,
                    borderRadius:4,padding:"2px 6px",
                  }}>{preset.eta}</span>
                  <div style={{
                    width:20,height:20,borderRadius:6,
                    background:"var(--bg-panel)",border:"0.5px solid var(--border-subtle)",
                    display:"flex",alignItems:"center",justifyContent:"center",
                    transition:"transform 0.2s var(--ease-out)",
                    transform:profileOpen?"rotate(180deg)":"rotate(0deg)",
                  }}>
                    <ChevronDown size={11} color="var(--text-secondary)"/>
                  </div>
                </div>
              </button>

              {/* Tool chips — always visible below trigger */}
              <div style={{marginTop:6,display:"flex",flexWrap:"wrap",gap:3}}>
                {activeTools.map(t=>{
                  const m=TOOL_META[t];
                  return(
                    <span key={t} style={{
                      display:"inline-flex",alignItems:"center",padding:"2px 7px",borderRadius:4,
                      background:"var(--bg-panel)",
                      border:`0.5px solid ${m.color}38`,
                      fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:m.color,
                    }}>{m.label}</span>
                  );
                })}
              </div>

              {/* Fixed-position floating dropdown — escapes overflow:hidden/auto */}
              {profileOpen&&(
                <div ref={profileDropRef} style={{
                  position:"fixed",
                  top:profilePos.top,
                  left:profilePos.left,
                  width:profilePos.width,
                  zIndex:9999,
                  background:"var(--bg-panel)",
                  border:`1px solid color-mix(in srgb,${preset.color} 50%,var(--border-default))`,
                  borderRadius:12,
                  boxShadow:"0 20px 60px rgba(0,0,0,0.7), 0 4px 16px rgba(0,0,0,0.4)",
                  overflow:"hidden",
                  animation:"dropdownIn 0.18s var(--ease-out) both",
                }}>
                  {/* Color accent top stripe */}
                  <div style={{height:2,background:`linear-gradient(90deg,transparent,${preset.color},transparent)`}}/>

                  {/* Options */}
                  {PRESETS.map(p=>{
                    const active=selectedPreset===p.id;
                    return(
                      <button key={p.id}
                        onClick={()=>{setSelectedPreset(p.id);setProfileOpen(false);}}
                        style={{
                          width:"100%",display:"flex",alignItems:"center",gap:10,
                          padding:"9px 14px",
                          background:active?`color-mix(in srgb,${p.color} 9%,var(--bg-surface))`:"transparent",
                          border:"none",
                          borderLeft:`3px solid ${active?p.color:"transparent"}`,
                          cursor:"pointer",transition:"background 0.12s",
                        }}
                        onMouseEnter={e=>{if(!active)e.currentTarget.style.background="var(--bg-surface)";}}
                        onMouseLeave={e=>{if(!active)e.currentTarget.style.background="transparent";}}
                      >
                        <div style={{
                          width:28,height:28,borderRadius:7,flexShrink:0,
                          background:active?`color-mix(in srgb,${p.color} 16%,var(--bg-panel))`:"var(--bg-hover)",
                          border:`0.5px solid ${active?`color-mix(in srgb,${p.color} 35%,transparent)`:"var(--border-subtle)"}`,
                          display:"flex",alignItems:"center",justifyContent:"center",
                          color:active?p.color:"var(--text-muted)",
                          transition:"all 0.15s",
                          boxShadow:active?`0 0 10px color-mix(in srgb,${p.color} 20%,transparent)`:"none",
                        }}>{p.icon}</div>

                        <div style={{flex:1,textAlign:"left",minWidth:0}}>
                          <div style={{fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:active?600:400,color:active?"var(--text-primary)":"var(--text-secondary)",lineHeight:1.1,marginBottom:1}}>
                            {p.label}
                            {p.requiresCreds&&<Lock size={8} style={{marginLeft:5,verticalAlign:"middle"}} color={active?p.color:"var(--text-faint)"}/>}
                          </div>
                          <div style={{fontFamily:"'Inter',sans-serif",fontSize:9,color:"var(--text-muted)"}}>{p.sublabel}</div>
                        </div>

                        <div style={{display:"flex",alignItems:"center",gap:6,flexShrink:0}}>
                          <span style={{
                            fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                            color:active?p.color:"var(--text-muted)",
                            background:active?`color-mix(in srgb,${p.color} 10%,transparent)`:"transparent",
                            border:active?`0.5px solid color-mix(in srgb,${p.color} 25%,transparent)`:"none",
                            borderRadius:3,padding:active?"1px 5px":"0",
                          }}>{p.eta}</span>
                          {active
                            ?<div style={{width:16,height:16,borderRadius:"50%",background:`color-mix(in srgb,${p.color} 15%,transparent)`,border:`1px solid ${p.color}`,display:"flex",alignItems:"center",justifyContent:"center"}}><Check size={9} color={p.color}/></div>
                            :<div style={{width:16,height:16,borderRadius:"50%",border:"1px solid var(--border-subtle)"}}/>
                          }
                        </div>
                      </button>
                    );
                  })}

                  {/* Footer — description + tool chips for highlighted/hovered preset */}
                  <div style={{padding:"8px 14px 10px",borderTop:"0.5px solid var(--border-subtle)",background:"var(--bg-sidebar)"}}>
                    <div style={{fontFamily:"'Inter',sans-serif",fontSize:10,color:"var(--text-secondary)",lineHeight:1.5,marginBottom:6}}>{preset.description}</div>
                    <div style={{display:"flex",flexWrap:"wrap",gap:3}}>
                      {(preset.id==="custom"?customTools:preset.tools).map(t=>{
                        const m=TOOL_META[t];
                        return(
                          <span key={t} style={{
                            display:"inline-flex",alignItems:"center",padding:"2px 7px",borderRadius:4,
                            background:"var(--bg-surface)",border:`0.5px solid ${m.color}45`,
                            fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:m.color,
                          }}>{m.label}</span>
                        );
                      })}
                      {preset.id==="custom"&&ALL_TOOLS.filter(t=>!customTools.includes(t)).map(t=>(
                        <button key={t} onClick={e=>{e.stopPropagation();setCustomTools(p=>[...p,t]);}}
                          style={{display:"inline-flex",alignItems:"center",padding:"2px 7px",borderRadius:4,background:"transparent",border:"0.5px dashed var(--border-subtle)",fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"var(--text-faint)",cursor:"pointer"}}
                          onMouseEnter={e=>{e.currentTarget.style.borderColor="var(--border-strong)";e.currentTarget.style.color="var(--text-muted)";}}
                          onMouseLeave={e=>{e.currentTarget.style.borderColor="var(--border-subtle)";e.currentTarget.style.color="var(--text-faint)";}}
                        >+ {TOOL_META[t].label}</button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* ── STEALTH — Segmented Control ── */}
            <div style={{padding:"12px 14px",borderBottom:"0.5px solid var(--border-subtle)"}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,fontWeight:700,color:"var(--text-faint)",letterSpacing:1.4,textTransform:"uppercase"}}>Stealth & Speed</span>
                <div style={{display:"flex",alignItems:"center",gap:6}}>
                  <span style={{fontFamily:"'Inter',sans-serif",fontSize:11,fontWeight:600,color:stealth.color,transition:"color 0.2s"}}>{stealth.label}</span>
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"var(--text-muted)"}}>{stealth.rate.toLocaleString()} pkt/s</span>
                </div>
              </div>

              {/* Segmented pill bar */}
              <div style={{
                display:"grid",gridTemplateColumns:"repeat(5,1fr)",
                background:"var(--bg-root)",
                border:"0.5px solid var(--border-subtle)",
                borderRadius:10,padding:3,gap:2,
              }}>
                {STEALTH_OPTS.map(s=>{
                  const active=stealth.id===s.id;
                  return(
                    <button key={s.id} onClick={()=>setStealth(s)} style={{
                      display:"flex",flexDirection:"column",alignItems:"center",gap:4,
                      padding:"7px 4px",borderRadius:7,cursor:"pointer",
                      background:active?`color-mix(in srgb,${s.color} 14%,var(--bg-panel))`:"transparent",
                      border:`0.5px solid ${active?s.color:"transparent"}`,
                      transition:"all 0.15s var(--ease-out)",
                      boxShadow:active?`0 2px 10px color-mix(in srgb,${s.color} 22%,transparent),inset 0 0 0 0.5px color-mix(in srgb,${s.color} 15%,transparent)`:"none",
                    }}
                      onMouseEnter={e=>{if(!active){e.currentTarget.style.background="var(--bg-hover)";e.currentTarget.style.borderColor="var(--border-subtle)";}}}
                      onMouseLeave={e=>{if(!active){e.currentTarget.style.background="transparent";e.currentTarget.style.borderColor="transparent";}}}
                    >
                      {/* Signal dot */}
                      <div style={{
                        width:7,height:7,borderRadius:"50%",
                        background:active?s.color:"var(--border-strong)",
                        boxShadow:active?`0 0 8px ${s.color},0 0 16px color-mix(in srgb,${s.color} 40%,transparent)`:"none",
                        transition:"all 0.15s",
                        flexShrink:0,
                      }}/>
                      {/* Short label */}
                      <span style={{
                        fontFamily:"'JetBrains Mono',monospace",fontSize:9,fontWeight:active?700:400,
                        color:active?s.color:"var(--text-muted)",
                        transition:"color 0.15s",letterSpacing:0.5,
                      }}>{s.short}</span>
                    </button>
                  );
                })}
              </div>

              {/* Info row */}
              <div style={{
                marginTop:8,display:"flex",alignItems:"center",justifyContent:"space-between",
                padding:"6px 10px",borderRadius:7,
                background:`color-mix(in srgb,${stealth.color} 5%,var(--bg-surface))`,
                border:`0.5px solid color-mix(in srgb,${stealth.color} 18%,transparent)`,
                transition:"all 0.2s",
              }}>
                <div style={{display:"flex",alignItems:"center",gap:6}}>
                  <div style={{width:5,height:5,borderRadius:"50%",background:stealth.color,boxShadow:`0 0 5px ${stealth.color}`}}/>
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"var(--text-muted)"}}>{stealth.timing} timing</span>
                </div>
                <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:stealth.color,fontWeight:600}}>{stealth.rate.toLocaleString()} pkt/s</span>
              </div>
            </div>

            {/* CREDENTIALS */}
            <div style={{padding:"10px 14px",borderBottom:"0.5px solid var(--border-subtle)"}}>
              <button onClick={()=>setShowCreds(p=>!p)} style={{
                width:"100%",display:"flex",alignItems:"center",gap:8,
                padding:"7px 10px",borderRadius:7,cursor:"pointer",
                border:`0.5px solid ${showCreds?"var(--accent)":"var(--border-subtle)"}`,
                background:showCreds?"var(--accent-ghost)":"var(--bg-surface)",transition:"all 0.15s",
              }}>
                <Lock size={11} color={showCreds?"var(--accent)":"var(--text-muted)"}/>
                <span style={{fontFamily:"'Inter',sans-serif",fontSize:11,color:showCreds?"var(--accent)":"var(--text-secondary)",flex:1,textAlign:"left"}}>
                  {creds.username?`${creds.domain}\\${creds.username}`:"Domain credentials"}
                </span>
                {preset.requiresCreds&&<span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:"var(--sev-medium-color)",background:"var(--sev-medium-bg)",border:"0.5px solid var(--sev-medium-color)",borderRadius:3,padding:"1px 4px"}}>REQ</span>}
                {showCreds?<ChevronUp size={10} color="var(--text-muted)"/>:<ChevronDown size={10} color="var(--text-muted)"/>}
              </button>
              {showCreds&&(
                <div style={{marginTop:8,display:"flex",flexDirection:"column",gap:5}}>
                  {[{key:"domain",label:"Domain",ph:"corp.local",type:"text"},{key:"dcIp",label:"DC IP",ph:"10.0.0.1",type:"text"},{key:"username",label:"Username",ph:"administrator",type:"text"},{key:"password",label:"Password",ph:"••••••••",type:"password"}].map(({key,label,ph,type})=>(
                    <div key={key}>
                      <div style={{fontFamily:"'Inter',sans-serif",fontSize:8,fontWeight:600,color:"var(--text-muted)",marginBottom:2,letterSpacing:0.5}}>{label.toUpperCase()}</div>
                      <input type={type} autoComplete="off" value={creds[key as keyof typeof creds]}
                        onChange={e=>setCreds(c=>({...c,[key]:e.target.value}))} placeholder={ph}
                        className="input-base" style={{fontSize:10,fontFamily:"'JetBrains Mono',monospace",height:28}}/>
                    </div>
                  ))}
                  <div style={{padding:"4px 8px",background:"var(--sev-medium-bg)",border:"0.5px solid var(--sev-medium-color)",borderRadius:5,fontFamily:"'Inter',sans-serif",fontSize:9,color:"var(--sev-medium-color)",display:"flex",alignItems:"center",gap:4}}>
                    <Lock size={8}/> Not logged or persisted
                  </div>
                </div>
              )}
            </div>

            {/* OPTIONS */}
            <div style={{padding:"10px 14px"}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                <span style={{fontFamily:"'Inter',sans-serif",fontSize:11,color:"var(--text-secondary)"}}>Auto-create findings</span>
                <div onClick={()=>setCreateFindings(p=>!p)} style={{width:32,height:17,borderRadius:9,position:"relative",cursor:"pointer",background:createFindings?"var(--accent)":"var(--bg-hover)",border:`0.5px solid ${createFindings?"var(--accent)":"var(--border-default)"}`,transition:"all 0.18s"}}>
                  <div style={{position:"absolute",top:2,left:createFindings?17:2,width:11,height:11,borderRadius:"50%",background:"#fff",transition:"left 0.18s",boxShadow:"0 1px 3px rgba(0,0,0,0.4)"}}/>
                </div>
              </div>
            </div>
          </div>

          {/* LAUNCH */}
          <div style={{padding:"10px 12px",borderTop:"0.5px solid var(--border-subtle)",background:"rgba(0,0,0,0.2)",flexShrink:0}}>
            {running?(
              <button onClick={()=>abortRef.current?.abort()} style={{
                width:"100%",padding:"11px",borderRadius:9,
                border:"0.5px solid var(--sev-critical-color)",background:"var(--sev-critical-bg)",
                color:"var(--sev-critical-color)",fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:700,cursor:"pointer",
                display:"flex",alignItems:"center",justifyContent:"center",gap:7,transition:"all 0.15s",
              }}
                onMouseEnter={e=>(e.currentTarget.style.background="rgba(255,77,77,0.15)")}
                onMouseLeave={e=>(e.currentTarget.style.background="var(--sev-critical-bg)")}
              ><Square size={12}/> Abort Scan</button>
            ):(
              <>
                <button onClick={startScan} disabled={!canLaunch} style={{
                  width:"100%",padding:"12px",borderRadius:9,
                  border:`0.5px solid ${canLaunch?"var(--accent)":"var(--border-subtle)"}`,
                  background:canLaunch?"var(--accent)":"var(--bg-surface)",
                  color:canLaunch?"#021820":"var(--text-muted)",
                  fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:700,
                  cursor:canLaunch?"pointer":"not-allowed",
                  display:"flex",alignItems:"center",justifyContent:"center",gap:7,
                  transition:"all 0.2s",
                  boxShadow:canLaunch?"0 2px 16px rgba(0,200,232,0.20)":"none",
                }}
                  onMouseEnter={e=>{if(canLaunch){e.currentTarget.style.boxShadow="0 4px 28px rgba(0,200,232,0.35)";e.currentTarget.style.transform="translateY(-1px)";}}}
                  onMouseLeave={e=>{e.currentTarget.style.boxShadow=canLaunch?"0 2px 16px rgba(0,200,232,0.20)":"none";e.currentTarget.style.transform="translateY(0)";}}
                >
                  <Play size={13} fill="currentColor"/>
                  {scan.phase==="complete"?"Run Again":"Launch Scan"}
                  {parseResult?.totalHosts?(
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,opacity:0.55}}>· {parseResult.totalHosts.toLocaleString()}</span>
                  ):null}
                </button>
                {isDone&&(
                  <button onClick={()=>dispatch({type:"RESET"})} style={{
                    marginTop:5,width:"100%",padding:"5px",borderRadius:7,
                    border:"0.5px solid var(--border-subtle)",background:"transparent",
                    color:"var(--text-muted)",fontFamily:"'Inter',sans-serif",fontSize:10,cursor:"pointer",
                    display:"flex",alignItems:"center",justifyContent:"center",gap:4,transition:"all 0.12s",
                  }}
                    onMouseEnter={e=>{e.currentTarget.style.borderColor="var(--border-strong)";e.currentTarget.style.color="var(--text-primary)";}}
                    onMouseLeave={e=>{e.currentTarget.style.borderColor="var(--border-subtle)";e.currentTarget.style.color="var(--text-muted)";}}
                  ><RotateCcw size={10}/> New Scan</button>
                )}
              </>
            )}
          </div>
        </div>

        {/* ════════════════════════════════════
            RIGHT — EXECUTION CANVAS
        ════════════════════════════════════ */}
        <div style={{display:"flex",flexDirection:"column",gap:12,overflow:"hidden"}}>

          {/* ── IDLE STATE ── */}
          {!hasRun&&(
            <div style={{
              flex:1,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",
              background:"var(--bg-panel)",border:"0.5px solid var(--border-subtle)",borderRadius:14,
              position:"relative",overflow:"hidden",
            }}>
              {/* Scanline effect */}
              <div style={{position:"absolute",inset:0,pointerEvents:"none",backgroundImage:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px)",zIndex:0}}/>

              {/* Radar rings */}
              <div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center",pointerEvents:"none",zIndex:1}}>
                {[320,240,160,80].map((d,i)=>(
                  <div key={d} style={{
                    position:"absolute",width:d,height:d,borderRadius:"50%",
                    border:"0.5px solid rgba(0,200,232,0.12)",
                    animation:`ring-pulse ${2.8+i*0.5}s ease-in-out infinite`,
                    animationDelay:`${i*0.5}s`,
                  }}/>
                ))}
                {/* Sweep */}
                <div style={{
                  position:"absolute",width:320,height:320,borderRadius:"50%",
                  background:"conic-gradient(from 0deg, transparent 0deg, rgba(0,200,232,0.05) 40deg, transparent 80deg)",
                  animation:"radar-sweep 5s linear infinite",
                }}/>
              </div>

              {/* Center content */}
              <div style={{position:"relative",zIndex:2,display:"flex",flexDirection:"column",alignItems:"center",gap:24}}>
                {/* Target reticle */}
                <div style={{position:"relative"}}>
                  {/* Outer ring */}
                  <div style={{
                    width:90,height:90,borderRadius:"50%",
                    border:"0.5px solid rgba(0,200,232,0.25)",
                    display:"flex",alignItems:"center",justifyContent:"center",
                    position:"relative",
                  }}>
                    {/* Tick marks */}
                    {[0,90,180,270].map(deg=>(
                      <div key={deg} style={{
                        position:"absolute",width:8,height:1,background:"rgba(0,200,232,0.30)",
                        transformOrigin:"left center",
                        transform:`rotate(${deg}deg) translateX(41px)`,
                      }}/>
                    ))}
                    {/* Inner circle */}
                    <div style={{
                      width:62,height:62,borderRadius:"50%",
                      border:"0.5px solid rgba(0,200,232,0.40)",
                      display:"flex",alignItems:"center",justifyContent:"center",
                      background:"rgba(0,200,232,0.04)",
                    }}>
                      <div style={{
                        width:36,height:36,borderRadius:"50%",
                        border:"1px solid var(--accent)",
                        display:"flex",alignItems:"center",justifyContent:"center",
                        background:"var(--accent-ghost)",
                        boxShadow:"0 0 24px var(--accent-glow)",
                      }}>
                        <Radio size={16} color="var(--accent)"/>
                      </div>
                    </div>
                  </div>
                  {/* Corner ticks */}
                  {[{t:-2,l:-2,btr:"1px solid var(--accent)",btl:"1px solid var(--accent)"},{t:-2,r:-2,btr:"1px solid var(--accent)",btr2:"1px solid var(--accent)"},{b:-2,l:-2},{b:-2,r:-2}].map((_,i)=>(
                    <div key={i} style={{
                      position:"absolute",
                      ...(i===0?{top:-2,left:-2,borderTop:"1.5px solid var(--accent)",borderLeft:"1.5px solid var(--accent)"}:
                         i===1?{top:-2,right:-2,borderTop:"1.5px solid var(--accent)",borderRight:"1.5px solid var(--accent)"}:
                         i===2?{bottom:-2,left:-2,borderBottom:"1.5px solid var(--accent)",borderLeft:"1.5px solid var(--accent)"}:
                               {bottom:-2,right:-2,borderBottom:"1.5px solid var(--accent)",borderRight:"1.5px solid var(--accent)"}),
                      width:12,height:12,
                    }}/>
                  ))}
                  {/* Blink dot */}
                  <div style={{position:"absolute",top:0,right:0,width:8,height:8,borderRadius:"50%",background:"var(--accent)",boxShadow:"0 0 10px var(--accent)",animation:"blink 1.2s step-end infinite"}}/>
                </div>

                <div style={{textAlign:"center"}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:12,fontWeight:700,color:"var(--text-muted)",letterSpacing:4,marginBottom:8}}>STANDBY</div>
                  <div style={{fontFamily:"'Inter',sans-serif",fontSize:19,fontWeight:700,color:"var(--text-primary)",letterSpacing:-0.5,marginBottom:6}}>Ready to scan</div>
                  <div style={{fontFamily:"'Inter',sans-serif",fontSize:12,color:"var(--text-secondary)",lineHeight:1.6}}>
                    Configure targets · select a profile · press{" "}
                    <span style={{color:"var(--accent)",fontWeight:600}}>Launch</span>
                  </div>
                </div>

                {/* CLI preview */}
                <div style={{
                  padding:"10px 18px",
                  background:"rgba(0,0,0,0.35)",
                  border:"0.5px solid var(--border-default)",
                  borderRadius:9,backdropFilter:"blur(4px)",
                  fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:"var(--text-secondary)",
                  display:"flex",alignItems:"center",gap:8,
                }}>
                  <span style={{color:"var(--accent)"}}>$</span>
                  <span> adversa scan </span>
                  <span style={{color:"var(--sev-medium-color)"}}>--target</span>
                  <span style={{color:"var(--text-primary)"}}>{rawTargets.split(/[\n,]+/)[0].trim()||"<target>"}</span>
                  <span style={{color:"var(--sev-medium-color)"}}>--mode</span>
                  <span style={{color:preset.color}}>{preset.id}</span>
                  <span style={{color:"var(--sev-medium-color)"}}>--stealth</span>
                  <span style={{color:stealth.color}}>{stealth.label.toLowerCase()}</span>
                  <span style={{animation:"blink 1s step-end infinite",color:"var(--accent)"}}>▊</span>
                </div>
              </div>
            </div>
          )}

          {/* ── ACTIVE / DONE ── */}
          {hasRun&&(
            <div style={{display:"flex",flexDirection:"column",gap:12,flex:1,overflow:"hidden"}}>

              {/* PIPELINE BAR */}
              <div style={{
                background:"var(--bg-panel)",
                border:`0.5px solid ${scan.phase==="error"?"rgba(255,77,77,0.3)":scan.phase==="complete"?"rgba(0,200,232,0.20)":"var(--border-subtle)"}`,
                borderRadius:12,padding:"12px 16px",flexShrink:0,
              }}>
                {/* Top row: progress + status */}
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                  <div style={{display:"flex",alignItems:"center",gap:12}}>
                    <span style={{
                      fontFamily:"'JetBrains Mono',monospace",fontSize:24,fontWeight:800,lineHeight:1,
                      color:scan.phase==="error"?"var(--sev-critical-color)":scan.phase==="complete"?"var(--accent)":"var(--text-primary)",
                    }}>{scan.overallProgress}%</span>
                    <div>
                      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"var(--text-muted)"}}>{fmtTime(scan.elapsed)}</div>
                      <div style={{fontFamily:"'Inter',sans-serif",fontSize:10,color:"var(--text-muted)"}}>{preset.label}</div>
                    </div>
                  </div>

                  <div style={{display:"flex",alignItems:"center",gap:10}}>
                    <div style={{width:160,height:4,background:"var(--border-subtle)",borderRadius:2,overflow:"hidden"}}>
                      <div style={{
                        height:"100%",width:`${scan.overallProgress}%`,borderRadius:2,transition:"width 0.5s ease",
                        background:scan.phase==="error"?"var(--sev-critical-color)":"var(--accent)",
                        position:"relative",overflow:"hidden",
                      }}>
                        {running&&<div style={{position:"absolute",inset:0,background:"linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)",backgroundSize:"200%",animation:"shimmer 1.5s infinite"}}/>}
                      </div>
                    </div>
                    <div style={{display:"flex",alignItems:"center",gap:5}}>
                      {scan.phase==="complete"&&<CheckCircle size={13} color="var(--accent)"/>}
                      {scan.phase==="error"&&<XCircle size={13} color="var(--sev-critical-color)"/>}
                      {running&&<div style={{width:6,height:6,borderRadius:"50%",background:"var(--accent)",animation:"pulse 1.5s ease-in-out infinite"}}/>}
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,letterSpacing:1,color:scan.phase==="complete"?"var(--accent)":scan.phase==="error"?"var(--sev-critical-color)":running?"var(--text-secondary)":"var(--text-muted)"}}>
                        {scan.phase==="complete"?"COMPLETE":scan.phase==="error"?"FAILED":running?"RUNNING":"–"}
                      </span>
                    </div>
                    {scan.phase==="complete"&&(
                      <button style={{display:"flex",alignItems:"center",gap:4,padding:"4px 10px",background:"rgba(0,200,232,0.08)",border:"0.5px solid rgba(0,200,232,0.20)",borderRadius:6,color:"var(--accent)",cursor:"pointer",fontFamily:"'Inter',sans-serif",fontSize:10,fontWeight:600}}>
                        <Download size={10}/> Export
                      </button>
                    )}
                  </div>
                </div>

                {/* Pipeline nodes */}
                <div style={{display:"flex",alignItems:"stretch",gap:0,overflowX:"auto",paddingBottom:2}}>
                  {activeTools.map((tool,i)=>(
                    <PipeNode key={tool} tool={tool} status={scan.stages[tool].status} progress={scan.stages[tool].progress} isLast={i===activeTools.length-1}/>
                  ))}
                </div>
              </div>

              {/* SEVERITY TILES */}
              <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,flexShrink:0}}>
                {(["CRITICAL","HIGH","MEDIUM","LOW"] as const).map(sev=>{
                  const count=sevCounts[sev];
                  const s=SEV[sev];
                  return(
                    <div key={sev} style={{
                      background:"var(--bg-panel)",
                      border:`0.5px solid ${count>0?s.color:"var(--border-subtle)"}`,
                      borderTop:`2.5px solid ${count>0?s.color:"var(--border-subtle)"}`,
                      borderRadius:10,padding:"10px 14px",
                      transition:"all 0.3s",
                      boxShadow:count>0?`0 4px 20px color-mix(in srgb,${s.color} 8%,transparent)`:"none",
                    }}>
                      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:26,fontWeight:800,color:count>0?s.color:"var(--text-faint)",lineHeight:1}}>{count}</div>
                      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"var(--text-muted)",marginTop:4,letterSpacing:1}}>{sev}</div>
                    </div>
                  );
                })}
              </div>

              {/* MAIN BODY */}
              <div style={{display:"grid",gridTemplateColumns:"1fr 220px",gap:12,flex:1,overflow:"hidden",minHeight:0}}>

                {/* Left: findings */}
                <div style={{background:"var(--bg-panel)",border:"0.5px solid var(--border-subtle)",borderRadius:12,overflow:"hidden",display:"flex",flexDirection:"column",minHeight:0}}>
                  <div style={{padding:"10px 14px",borderBottom:"0.5px solid var(--border-subtle)",display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      <span style={{fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:600,color:"var(--text-primary)"}}>Live Findings</span>
                      {scan.findings.length>0&&(
                        <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"var(--accent)",background:"var(--accent-ghost)",borderRadius:10,padding:"1px 7px"}}>{scan.findings.length}</span>
                      )}
                    </div>
                    {running&&(
                      <div style={{display:"flex",alignItems:"center",gap:5}}>
                        <div style={{width:5,height:5,borderRadius:"50%",background:"var(--accent)",animation:"pulse 1.5s ease-in-out infinite"}}/>
                        <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"var(--accent)",letterSpacing:1}}>LIVE</span>
                      </div>
                    )}
                  </div>
                  <div style={{overflowY:"auto",flex:1}}>
                    {scan.findings.length===0?(
                      <div style={{padding:"40px 16px",textAlign:"center",fontFamily:"'Inter',sans-serif",fontSize:12,color:"var(--text-muted)"}}>
                        {running?"Scanning… findings appear here in real time":"No findings recorded"}
                      </div>
                    ):(
                      scan.findings.map((f,i)=>{
                        const s=SEV[f.severity]??SEV.INFO;
                        return(
                          <div key={i} className="scan-finding-row" style={{
                            padding:"9px 14px",borderBottom:"0.5px solid var(--border-subtle)",
                            display:"flex",gap:10,alignItems:"flex-start",
                            borderLeft:`3px solid ${s.color}`,
                            cursor:"default",transition:"background 0.1s",
                          }}
                            onMouseEnter={e=>(e.currentTarget.style.background="var(--bg-hover)")}
                            onMouseLeave={e=>(e.currentTarget.style.background="transparent")}
                          >
                            <div style={{flex:1,minWidth:0}}>
                              <div style={{fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:500,color:"var(--text-primary)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{f.title}</div>
                              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"var(--text-muted)",marginTop:2}}>{f.host} · {f.source}</div>
                            </div>
                            <span style={{
                              fontFamily:"'JetBrains Mono',monospace",fontSize:8,fontWeight:700,flexShrink:0,
                              color:s.color,background:s.bg,
                              border:`0.5px solid ${s.color}30`,borderRadius:4,padding:"2px 6px",
                            }}>{f.severity}</span>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Right: hosts + terminal stacked */}
                <div style={{display:"flex",flexDirection:"column",gap:10,overflow:"hidden",minHeight:0}}>

                  {/* Host grid */}
                  <div style={{background:"var(--bg-panel)",border:"0.5px solid var(--border-subtle)",borderRadius:12,padding:"12px 14px",flexShrink:0}}>
                    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                      <span style={{fontFamily:"'Inter',sans-serif",fontSize:12,fontWeight:600,color:"var(--text-primary)"}}>Hosts</span>
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:"var(--accent)"}}>{scan.hosts.length}</span>
                    </div>
                    {scan.hosts.length===0?(
                      <div style={{fontFamily:"'Inter',sans-serif",fontSize:11,color:"var(--text-muted)",textAlign:"center",padding:"14px 0"}}>
                        {running?"Discovering…":"None yet"}
                      </div>
                    ):(
                      <div style={{display:"flex",flexWrap:"wrap",gap:5,maxHeight:120,overflowY:"auto"}}>
                        {scan.hosts.map(h=>{
                          const col=h.risk==="critical"?"var(--sev-critical-color)":h.risk==="high"?"var(--sev-high-color)":h.risk==="medium"?"var(--sev-medium-color)":"var(--accent)";
                          return(
                            <div key={h.ip} title={`${h.ip}${h.hostname?` (${h.hostname})`:""} · ${h.ports} ports`}
                              style={{
                                width:32,height:32,borderRadius:7,
                                background:`color-mix(in srgb,${col} 8%,var(--bg-surface))`,
                                border:`1px solid color-mix(in srgb,${col} 25%,var(--border-subtle))`,
                                display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",
                                transition:"all 0.15s",
                              }}
                              onMouseEnter={e=>{e.currentTarget.style.transform="scale(1.2)";e.currentTarget.style.boxShadow=`0 0 10px color-mix(in srgb,${col} 35%,transparent)`;e.currentTarget.style.borderColor=col;}}
                              onMouseLeave={e=>{e.currentTarget.style.transform="scale(1)";e.currentTarget.style.boxShadow="none";e.currentTarget.style.borderColor=`color-mix(in srgb,${col} 25%,var(--border-subtle))`;}}
                            >
                              {h.hasAD?<Shield size={12} color={col}/>:h.hasWeb?<Globe size={12} color={col}/>:<Server size={12} color={col}/>}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Terminal */}
                  <div style={{background:"#060a10",border:"0.5px solid #161c2a",borderRadius:12,overflow:"hidden",flex:1,display:"flex",flexDirection:"column",minHeight:0}}>
                    <div style={{padding:"6px 10px",borderBottom:"0.5px solid #161c2a",display:"flex",alignItems:"center",gap:7,background:"#090e18",flexShrink:0}}>
                      <div style={{display:"flex",gap:4}}>
                        <div style={{width:8,height:8,borderRadius:"50%",background:"#FF5F57"}}/>
                        <div style={{width:8,height:8,borderRadius:"50%",background:"#FEBC2E"}}/>
                        <div style={{width:8,height:8,borderRadius:"50%",background:"#28C840"}}/>
                      </div>
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:"rgba(255,255,255,0.2)",flex:1,textAlign:"center"}}>adversa · output</span>
                      {scan.logs.length>0&&<CopyBtn text={scan.logs.join("\n")}/>}
                    </div>
                    <div ref={logRef} style={{flex:1,overflowY:"auto",padding:"8px 10px",fontFamily:"'JetBrains Mono',monospace",fontSize:9,lineHeight:1.9}}>
                      {scan.logs.length===0?(
                        <span style={{color:"rgba(255,255,255,0.12)"}}>Waiting…</span>
                      ):(
                        scan.logs.map((line,i)=>{
                          const col=
                            line.includes("[ERROR]")||line.includes("failed")?"#FF5252":
                            line.includes("◆")||line.includes("[CRITICAL]")?"var(--sev-critical-color)":
                            line.includes("[HIGH]")?"var(--sev-high-color)":
                            line.includes("↑")||line.includes("HOST")?"#26C6DA":
                            line.includes("✓")||line.includes("Complete")?"var(--accent)":
                            line.includes("Launching")||line.includes("Tools")?"rgba(255,255,255,0.6)":
                            "rgba(255,255,255,0.3)";
                          return<div key={i} style={{color:col}}>{line}</div>;
                        })
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
