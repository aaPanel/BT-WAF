import{d as e,X as t,r as a,o as l,S as n,f as s,e as i,P as c,aa as o,U as r,$ as u,k as d,F as p,a2 as v,a3 as m,u as f,b as _,ad as x,m as h,W as b,Z as w,s as y,p as A}from"./vue.314199b7.1742181728921.js";import{cA as g,cD as T,cB as C,f as k,_ as $,A as j,cE as R,R as U,cF as z,cG as O,l as B,m as E,n as I,u as M,cH as S,S as L,aD as P,aG as W}from"./index.fc641b56.1742181728921.js";import{_ as F}from"./index.1264c2ce.1742181728921.js";import{_ as N}from"./index.f87a01d3.1742181728921.js";import{_ as q}from"./index.29125cc8.1742181728921.js";import{N as D}from"./InputNumber.f6532dc5.1742181728921.js";import{_ as G}from"./index.vue_vue_type_script_setup_true_lang.141d1f64.1742181728921.js";import{a as H}from"./DataTable.762c357a.1742181728921.js";import{a as V,_ as Z}from"./BreadcrumbItem.fb658c61.1742181728921.js";import"./layer.8f9c8930.1742181728921.js";import"./Checkbox.64335fca.1742181728921.js";import"./get-slot.a0e67e91.1742181728921.js";import"./utils.d31cac41.1742181728921.js";const K={class:"w-350px"},Q=r("p",null,"请输入您需要清理缓存的URL，如：",-1),X=r("p",null,"https://bt.cn/path/*",-1),J=r("p",null,"https://bt.cn/cache.html",-1),Y=e({__name:"index",setup(e,{expose:r}){const u=g(),{site:d}=t(u),p=a("");return r({onConfirm:async e=>{await T({site_id:d.value.site_id,site_name:d.value.site_name,type:"2",uri:p.value}),e()}}),(e,t)=>{const a=q;return l(),n("div",K,[s(a,{value:c(p),"onUpdate:value":t[0]||(t[0]=e=>o(p)?p.value=e:null),rows:8},{default:i((()=>[Q,X,J])),_:1},8,["value"])])}}}),ee={class:"w-390px p-30px main-box"},te=(e=>(v("data-v-7a68bc91"),e=e(),m(),e))((()=>r("div",{class:"icon"},null,-1))),ae={class:"tip"},le={class:"footer-btn"},ne=$(e({__name:"index",emits:["close"],setup(e,{emit:a}){const c=g(),{site:o}=t(c),v=async()=>{const e={site_id:o.value.site_id,site_name:o.value.site_name,type:"1"};await T({...e,uri:""}),await C({...e}),m()},m=()=>{a("close")};return(e,t)=>{const a=k;return l(),n(p,null,[r("div",ee,[te,r("div",ae,u(e.$t("Acceleration.ClearAllModal.Content")),1)]),r("div",le,[s(a,{size:"small",class:"cancel-btn",color:"#cbcbcb",onClick:m},{default:i((()=>[d(u(e.$t("Public.Btn.Cancel")),1)])),_:1}),s(a,{type:"warning",size:"small",onClick:v},{default:i((()=>[d(u(e.$t("Acceleration.ClearAllBtn")),1)])),_:1})])],64)}}}),[["__scopeId","data-v-7a68bc91"]]),se={class:"mb-8px flex justify-between"},ie={class:"text-15px"},ce=r("div",null,null,-1),oe={class:"flex items-center"},re={class:"flex-1"},ue={class:"text-desc"},de=e({__name:"index",setup(e){const n=g(),{site:p}=t(n),v=a(!1),m=f({show:!1,title:"清理页面缓存 - 【".concat(p.value.site_name,"】")});return(e,t)=>{const a=k,n=j,p=N;return l(),_(p,null,{default:i((()=>[r("div",se,[r("div",ie,u(e.$t("Acceleration.Title.Cache")),1),ce]),r("div",oe,[r("div",re,[r("div",ue,u(e.$t("Acceleration.Tip.CacheCon")),1)]),s(a,{type:"primary",size:"small",ghost:"",onClick:t[0]||(t[0]=e=>v.value=!0)},{default:i((()=>[d(u(e.$t("Acceleration.ClearAllBtn")),1)])),_:1})]),s(n,{show:c(m).show,"onUpdate:show":t[1]||(t[1]=e=>c(m).show=e),title:c(m).title,"is-footer":!0,"confirm-text":"立即清理",component:Y},null,8,["show","title"]),s(n,{show:c(v),"onUpdate:show":t[2]||(t[2]=e=>o(v)?v.value=e:null),title:e.$t("Acceleration.ClearAllModal.Title"),padding:"0",component:ne},null,8,["show","title"])])),_:1})}}}),pe=e({__name:"index",setup:e=>(e,t)=>{const a=F;return l(),n("div",null,[s(a,null,{default:i((()=>[d(u(e.$t("Acceleration.Title.Cache")),1)])),_:1}),s(de)])}}),ve={class:"mb-8px text-15px"},me={class:"text-desc"},fe={class:"flex items-end"},_e={class:"flex-1"},xe={class:"flex flex-wrap items-center mb-8px"},he={class:"w-90px ml-8px mr-18px"},be={class:"tip"},we={class:"w-90px ml-8px mr-8px"},ye={class:"flex justify-between"},Ae=$(e({__name:"index",setup(e){const a=g(),{site:n}=t(a),o=f({expire:n.value.config.expire,size:n.value.config.size}),p=async()=>{const e={...x(o),site_name:n.value.site_name,site_id:n.value.site_id};await R(e),n.value.config.expire=o.expire,n.value.config.size=o.size};return(e,t)=>{const a=U,n=D,v=k,m=N;return l(),_(m,null,{default:i((()=>[r("div",ve,u(e.$t("Acceleration.Title.Config")),1),r("div",me,u(e.$t("Acceleration.Tip.ConfigCon")),1),s(a),r("div",fe,[r("div",_e,[r("div",xe,[r("span",null,u(e.$t("Acceleration.Tip.CacheTime")),1),r("div",he,[s(n,{value:c(o).expire,"onUpdate:value":t[0]||(t[0]=e=>c(o).expire=e),size:"small","show-button":!1,min:"3600"},{suffix:i((()=>[d(u(e.$t("Public.Unit.Seconds")),1)])),_:1},8,["value"]),r("div",be,u(e.$t("Acceleration.Tip.Note")),1)]),r("span",null,u(e.$t("Acceleration.Tip.Greater")),1),r("div",we,[s(n,{value:c(o).size,"onUpdate:value":t[1]||(t[1]=e=>c(o).size=e),size:"small","show-button":!1},{suffix:i((()=>[d("MB")])),_:1},8,["value"])]),r("span",null,u(e.$t("Acceleration.Tip.NotCach")),1)])]),r("div",ye,[s(v,{type:"primary",ghost:"",size:"small",onClick:p},{default:i((()=>[d(u(e.$t("Public.Btn.Save")),1)])),_:1})])])])),_:1})}}}),[["__scopeId","data-v-0d1fde52"]]),ge={class:"w-380px px-30px pt-10px"},Te=e({__name:"add",setup(e,{expose:o}){const{row:r,isEdit:u,callback:d}=h("component-data")||{},p=g(),{site:v}=t(p),m=a(null),_=f({value:{trigger:"blur",validator:()=>""!==b.value||new Error("请输入匹配内容")}}),b=f({site_name:v.value.site_name,obj:"uri",type:"prefix",value:""}),w=[{label:"URI地址",value:"uri"},{label:"请求参数",value:"args"},{label:"后缀名",value:"ext"},{label:"域名",value:"host"},{label:"ip转数字型",value:"ipv4"},{label:"响应类型",value:"type"},{label:"请求方式",value:"method"}],y=[{label:"匹配开头",value:"prefix"},{label:"匹配结尾",value:"suffix"},{label:"完全等于",value:"="},{label:"包含关键字",value:"keyword"},{label:"正则匹配",value:"match"}];o({onConfirm:async e=>{var t;await(null==(t=m.value)?void 0:t.validate()),u?await z({...x(b),site_id:v.value.site_id,form:"force",key:r.key}):await O({...x(b),site_id:v.value.site_id,form:"force"}),null==d||d(),e()}});return u&&(b.obj=r.obj,b.type=r.type,b.value=r.value),(e,t)=>{const a=B,o=E,r=H,u=I;return l(),n("div",ge,[s(u,{ref_key:"formRef",ref:m,rules:c(_),"label-placement":"left","label-width":"80"},{default:i((()=>[s(o,{label:"网站"},{default:i((()=>[s(a,{value:c(b).site_name,"onUpdate:value":t[0]||(t[0]=e=>c(b).site_name=e),disabled:!0},null,8,["value"])])),_:1}),s(o,{label:"规则类型","show-require-mark":!0},{default:i((()=>[s(r,{value:c(b).obj,"onUpdate:value":t[1]||(t[1]=e=>c(b).obj=e),options:w},null,8,["value"])])),_:1}),s(o,{label:"匹配访问","show-require-mark":!0},{default:i((()=>[s(r,{value:c(b).type,"onUpdate:value":t[2]||(t[2]=e=>c(b).type=e),options:y},null,8,["value"])])),_:1}),s(o,{label:"匹配内容","show-require-mark":!0,placeholder:"请输入匹配内容",path:"value"},{default:i((()=>[s(a,{value:c(b).value,"onUpdate:value":t[3]||(t[3]=e=>c(b).value=e),spellcheck:"false"},null,8,["value"])])),_:1})])),_:1},8,["rules"])])}}}),Ce={class:"w-700px p-16px"},ke=$(e({__name:"index",setup(e){const{t:i}=b(),o=g(),{site:r}=t(o),u=f({data:[]}),{loading:d,setLoading:p}=M(),v=async()=>{try{p(!0);const{res:e}=await S({site_id:r.value.site_id,site_name:r.value.site_name,form:"force"}),{0:t}=e;u.data=t||[]}finally{p(!1)}},m=f({show:!1,title:"",data:{row:{},isEdit:!1,callback:v}}),_=new Map([["args","".concat(i("Acceleration.TypeOption.Args"))],["ext","".concat(i("Acceleration.TypeOption.Ext"))],["host","".concat(i("Acceleration.TypeOption.Host"))],["ipv4","".concat(i("Acceleration.TypeOption.Ipv4"))],["type","".concat(i("Acceleration.TypeOption.Type"))],["method","".concat(i("Acceleration.TypeOption.Method"))],["uri","".concat(i("Acceleration.TypeOption.Uri"))]]),x=new Map([["prefix","".concat(i("Acceleration.RuleOption.Prefix"))],["suffix","".concat(i("Acceleration.RuleOption.Suffix"))],["=","".concat(i("Acceleration.RuleOption.Equal"))],["keyword","".concat(i("Acceleration.RuleOption.Keyword"))],["match","".concat(i("Acceleration.RuleOption.Match"))]]),h=a([{key:"obj",title:"".concat(i("Acceleration.CheckModal.Table.Obj")),width:80,minWidth:60,render:e=>_.get(e.obj)||"-"},{key:"value",title:"".concat(i("Acceleration.CheckModal.Table.Value")),width:100,minWidth:100},{key:"type",title:"".concat(i("Acceleration.CheckModal.Table.Type")),width:80,minWidth:50,render:e=>x.get(e.type)||"-"}]);return v(),(e,t)=>{const a=G,i=j;return l(),n("div",Ce,[s(a,{loading:c(d),data:c(u).data,columns:c(h),"max-height":400},null,8,["loading","data","columns"]),s(i,{show:c(m).show,"onUpdate:show":t[0]||(t[0]=e=>c(m).show=e),title:c(m).title,data:c(m).data,"is-footer":!0,"confirm-text":e.$t("Public.Btn.Save"),component:Te},null,8,["show","title","data","confirm-text"])])}}}),[["__scopeId","data-v-8ba564c4"]]),$e={class:"flex items-end"},je={class:"flex-1"},Re={class:"mb-16px text-15px"},Ue={class:"text-desc"},ze=e({__name:"index",setup(e){const{t:a}=b(),n=g(),{site:o}=t(n),p=f({show:!1,title:"".concat(a("Acceleration.CheckModal.Title")," - 【").concat(o.value.site_name,"】"),data:{}}),v=()=>{p.show=!0};return(e,t)=>{const a=k,n=j,o=N;return l(),_(o,{class:"mt-12px"},{default:i((()=>[r("div",$e,[r("div",je,[r("div",Re,u(e.$t("Acceleration.Title.Rule")),1),r("div",Ue,u(e.$t("Acceleration.Tip.RuleCon")),1)]),s(a,{type:"primary",size:"small",ghost:"",onClick:v},{default:i((()=>[d(u(e.$t("Acceleration.CheckBtn")),1)])),_:1})]),s(n,{show:c(p).show,"onUpdate:show":t[0]||(t[0]=e=>c(p).show=e),title:c(p).title,padding:"0",data:c(p).data,component:ke},null,8,["show","title","data"])])),_:1})}}}),Oe={class:"mt-20px"},Be=e({__name:"index",setup:e=>(e,t)=>{const a=F;return l(),n("div",Oe,[s(a,null,{default:i((()=>[d(u(e.$t("Acceleration.Title.StaticCache")),1)])),_:1}),s(Ae),s(ze)])}}),Ee=e=>(v("data-v-3a80973e"),e=e(),m(),e),Ie={class:"p-16px"},Me={class:"rule-box"},Se={class:"menu"},Le={class:"rule-content"},Pe={class:"max-w-1000px"},We=Ee((()=>r("div",{id:"cache-ref"},null,-1))),Fe=Ee((()=>r("div",{id:"config-ref"},null,-1))),Ne=$(e({__name:"index",setup(e){const d=g(),{site:p}=t(d),v=w(),m=a("cache");let f=!1;const _=()=>{const e=document.getElementById("layout-content");if(!e)return null;const t=e.getElementsByClassName("n-scrollbar-container");return 0===t.length?null:t[0]},x=e=>{f=!0;const t=document.getElementById("".concat(e,"-ref"));if(t){const e=t.offsetTop,a=_();null==a||a.scrollTo({top:e,behavior:"smooth"}),setTimeout((()=>{f=!1}),600)}},h=new Map([["cache",0],["config",0]]),b=e=>{if(f)return;const t=e.target.scrollTop,a=Array.from(h.keys()),l=Array.from(h.values()).findIndex((e=>e>t));if(l>0){const e=a[l-1];m.value=e.replace("-ref","")}},T=a(),C=a(),k=a(),$=a(),j=new ResizeObserver((e=>{const{width:t}=e[0].contentRect;C.value&&(C.value.style.width="".concat(t-16,"px"));const a=$.value.$el;k.value&&(k.value.style.width="".concat(a.clientWidth,"px"))}));y((()=>{h.forEach(((e,t)=>{const a=document.getElementById(t);a&&h.set(t,a.offsetTop-300)})),(()=>{const e=_();null==e||e.addEventListener("scroll",b)})(),T.value&&j.observe(T.value)})),A((()=>{j.disconnect(),(()=>{const e=_();null==e||e.removeEventListener("scroll",b)})()}));const R=()=>{v.push("/acceleration")};return d.getList(),(e,t)=>{const a=V,d=Z,v=P,f=W,_=L;return l(),n("div",{ref_key:"configRef",ref:T,class:"flex flex-col"},[r("div",{ref_key:"shelterRef",ref:C,class:"fixed bg-[#F2F2F2] min-w-300px h-16px z-1"},null,512),r("div",Ie,[s(_,{ref_key:"cardRef",ref:$,"content-style":{padding:0}},{default:i((()=>[r("div",{ref_key:"navRef",ref:k,class:"rule-nav"},[s(d,null,{default:i((()=>[s(a,{onClick:R},{default:i((()=>[r("span",null,u(e.$t("Acceleration.Title.List")),1)])),_:1}),s(a,null,{default:i((()=>[r("span",null,u(c(p).site_name),1)])),_:1})])),_:1})],512),r("div",Me,[r("div",Se,[s(f,{value:c(m),"onUpdate:value":[t[0]||(t[0]=e=>o(m)?m.value=e:null),x],placement:"left"},{default:i((()=>[s(v,{name:"cache",tab:e.$t("Acceleration.Title.Cache")},null,8,["tab"]),s(v,{name:"config",tab:e.$t("Acceleration.Title.StaticCache")},null,8,["tab"])])),_:1},8,["value"])]),r("div",Le,[r("div",Pe,[We,s(pe),Fe,s(Be)])])])])),_:1},512)])],512)}}}),[["__scopeId","data-v-3a80973e"]]);export{Ne as default};
