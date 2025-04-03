import{cI as e,i as t,l as a,m as l,f as o,n as s,S as d,$ as n,u as r,o as i,A as p}from"./index.fc641b56.1742181728921.js";import{_ as c}from"./index.vue_vue_type_script_setup_true_lang.141d1f64.1742181728921.js";import{d as _,W as u,u as m,r as b,o as v,b as f,e as P,f as h,U as w,P as g,k as x,$ as y,ad as k,m as U,S as C,F as T,l as O}from"./vue.314199b7.1742181728921.js";import{a as F}from"./DataTable.762c357a.1742181728921.js";import{_ as L}from"./utils.d31cac41.1742181728921.js";import"./layer.8f9c8930.1742181728921.js";import"./Checkbox.64335fca.1742181728921.js";import"./get-slot.a0e67e91.1742181728921.js";const j={class:"flex"},q={class:"w-200px"},A={class:"w-100px ml-10px"},N={class:"w-310px"},$={class:"flex"},W={class:"w-200px"},D={class:"w-200px"},E={class:"w-200px"},S=_({__name:"index",emits:["refresh"],setup(n,{emit:r}){const{t:i}=u(),p=m({protocol:"tcp",listen_address:"127.0.0.1",listen_port:"",max_timeout:"8",not_timeout:"86400",node_info:[{node_address:"",node_port:"",node_status:"1",node_weight:"1",node_max_fails:"2",node_fail_timeout:"600",node_address_follow:!1,ps:""}],ps:"测试"}),c=[{label:"TCP",value:"tcp"},{label:"UDP",value:"udp"},{label:"TCP/UDP",value:"tcp/udp"}],_=[{label:"".concat(i("Port.IpOption.0")),value:"127.0.0.1"},{label:"".concat(i("Port.IpOption.1")),value:"0.0.0.0"}],U=m({listen_port:{trigger:"blur",required:!0,validator:()=>""!==p.listen_port||new Error("".concat(i("Port.Form.Port.Placeholder")))},node_address:{trigger:"blur",required:!0,validator:()=>""!==p.node_info[0].node_address||new Error("".concat(i("Port.Form.NodeAdd.Placeholder")))},node_port:{trigger:"blur",required:!0,validator:()=>""!==p.node_info[0].node_port||new Error("".concat(i("Port.Form.NodePort.Placeholder")))}}),C=b(null),T=async()=>{var a,l;await(null==(a=C.value)?void 0:a.validate()),await(l={...k(p)},e.post("/nginx/add_tcp_load_balance",l,{requestOptions:{loading:t.global.t("Api.Port.Add"),globalSuccessMessage:!0}})),O(),r("refresh")},O=()=>{p.protocol="tcp",p.listen_port="",p.node_info[0].node_address="",p.node_info[0].node_port="",p.node_info[0].ps="",p.listen_address="127.0.0.1"};return(e,t)=>{const n=a,r=F,i=l,u=o,m=s,b=d;return v(),f(b,{class:"mb-16px",title:e.$t("Port.Form.Title")},{default:P((()=>[h(m,{ref_key:"formRef",ref:C,model:g(p),rules:g(U),"label-width":"130px","label-placement":"left","require-mark-placement":"left"},{default:P((()=>[h(i,{label:e.$t("Port.Form.Port.Name"),path:"listen_port"},{default:P((()=>[w("div",j,[w("div",q,[h(n,{value:g(p).listen_port,"onUpdate:value":t[0]||(t[0]=e=>g(p).listen_port=e),placeholder:e.$t("Port.Form.Port.Placeholder")},null,8,["value","placeholder"])]),w("div",A,[h(r,{value:g(p).protocol,"onUpdate:value":t[1]||(t[1]=e=>g(p).protocol=e),options:c},null,8,["value"])])])])),_:1},8,["label"]),h(i,{label:e.$t("Port.Form.Listen"),"show-require-mark":!0},{default:P((()=>[w("div",N,[h(r,{value:g(p).listen_address,"onUpdate:value":t[2]||(t[2]=e=>g(p).listen_address=e),options:_},null,8,["value"])])])),_:1},8,["label"]),w("div",$,[h(i,{label:e.$t("Port.Form.NodeAdd.Name"),path:"node_address"},{default:P((()=>[w("div",W,[h(n,{value:g(p).node_info[0].node_address,"onUpdate:value":t[3]||(t[3]=e=>g(p).node_info[0].node_address=e),spellcheck:"false",placeholder:e.$t("Port.Form.NodeAdd.Placeholder")},null,8,["value","placeholder"])])])),_:1},8,["label"]),h(i,{label:e.$t("Port.Form.NodePort.Name"),"label-width":"100px",path:"node_port"},{default:P((()=>[w("div",D,[h(n,{value:g(p).node_info[0].node_port,"onUpdate:value":t[4]||(t[4]=e=>g(p).node_info[0].node_port=e),spellcheck:"false",placeholder:e.$t("Port.Form.NodePort.Placeholder")},null,8,["value","placeholder"])])])),_:1},8,["label"])]),h(i,{label:e.$t("Port.Form.Ps.Name")},{default:P((()=>[w("div",E,[h(n,{value:g(p).node_info[0].ps,"onUpdate:value":t[5]||(t[5]=e=>g(p).node_info[0].ps=e),spellcheck:"false",placeholder:e.$t("Port.Form.Ps.Name")},null,8,["value","placeholder"])])])),_:1},8,["label"]),h(i,{label:" ","show-feedback":!1},{default:P((()=>[h(u,{type:"primary",onClick:T},{default:P((()=>[x(y(e.$t("Public.Btn.Add")),1)])),_:1})])),_:1})])),_:1},8,["model","rules"])])),_:1},8,["title"])}}}),M={class:"600px"},I={class:"flex"},B={class:"w-200px"},R={class:"w-100px ml-10px"},z={class:"w-310px"},H={class:"flex"},G={class:"w-200px"},J={class:"w-200px"},K=_({__name:"index",setup(o,{expose:d}){const{row:r,callback:i}=U("component-data")||{},p=m({protocol:"tcp",listen_address:"127.0.0.1",listen_port:"",node_address:"",node_port:"",ps:""}),c=[{label:"TCP",value:"tcp"},{label:"UDP",value:"udp"},{label:"TCP/UDP",value:"tcp/udp"}],_=[{label:"127.0.0.1 - 仅允许本服务器访问",value:"127.0.0.1"},{label:"0.0.0.0 - 允许所有人访问",value:"0.0.0.0"}],u=m({listen_port:{trigger:"blur",required:!0,validator:()=>""!==p.listen_port||new Error("请输入云WAF服务端口")},node_address:{trigger:"blur",required:!0,validator:()=>""!==p.node_address||new Error("请输入目标主机")},node_port:{trigger:"blur",required:!0,validator:()=>""!==p.node_port||new Error("请输入目标主端口号")}}),f=b(null),x=b("");d({onConfirm:async a=>{var l;await(null==(l=f.value)?void 0:l.validate()),n({title:"提示",content:"修改端口转发时，会重启Nginx影响网站访问，是否继续修改？",onConfirm:async()=>{const l=(()=>{const e=r.node_address_map[x.value];return{load_balance_name:r.load_balance_name,load_info:{load_balance_name:r.load_balance_name,max_timeout:r.max_timeout,listen_address:p.listen_address,node_address_map:{[x.value]:{fail_timeout:e.fail_timeout,max_fails:e.max_fails,node_address:p.node_address,node_address_follow:!1,node_port:p.node_port,ps:p.ps,status:e.status,weight:e.weight}},not_timeout:r.not_timeout,protocol:p.protocol,ps:r.ps}}})();await(a=>e.post("/nginx/modify_tcp_load_balance",a,{requestOptions:{loading:t.global.t("Api.Port.Edit"),globalSuccessMessage:!0}}))(l),null==i||i(),a()}})}});var y;return x.value=(y=r,Object.keys(y.node_address_map)[0]),p.protocol=r.protocol,p.listen_address=r.listen_address,p.listen_port=r.listen_port,p.node_address=r.node_address_map[x.value].node_address,p.node_port=r.node_address_map[x.value].node_port,p.ps=r.node_address_map[x.value].ps,(e,t)=>{const o=a,d=F,n=l,r=s;return v(),C("div",M,[h(r,{ref_key:"formRef",ref:f,model:g(p),rules:g(u),"label-width":"130px","label-placement":"left","require-mark-placement":"left"},{default:P((()=>[h(n,{label:"云WAF服务端口",path:"listen_port"},{default:P((()=>[w("div",I,[w("div",B,[h(o,{value:g(p).listen_port,"onUpdate:value":t[0]||(t[0]=e=>g(p).listen_port=e),spellcheck:"false",disabled:!0,placeholder:"请输入端口号"},null,8,["value"])]),w("div",R,[h(d,{value:g(p).protocol,"onUpdate:value":t[1]||(t[1]=e=>g(p).protocol=e),options:c},null,8,["value"])])])])),_:1}),h(n,{label:"监听地址","show-require-mark":!0},{default:P((()=>[w("div",z,[h(d,{value:g(p).listen_address,"onUpdate:value":t[2]||(t[2]=e=>g(p).listen_address=e),options:_},null,8,["value"])])])),_:1}),w("div",H,[h(n,{label:"目标主机",path:"node_address"},{default:P((()=>[w("div",G,[h(o,{value:g(p).node_address,"onUpdate:value":t[3]||(t[3]=e=>g(p).node_address=e)},null,8,["value"])])])),_:1}),h(n,{label:"目标端口","label-width":"90px",path:"node_port"},{default:P((()=>[h(o,{value:g(p).node_port,"onUpdate:value":t[4]||(t[4]=e=>g(p).node_port=e)},null,8,["value"])])),_:1})]),h(n,{label:"备注","show-feedback":!1},{default:P((()=>[w("div",J,[h(o,{value:g(p).ps,"onUpdate:value":t[5]||(t[5]=e=>g(p).ps=e)},null,8,["value"])])])),_:1})])),_:1},8,["model","rules"])])}}}),Q={class:"p-16px"},V=w("p",{class:"text-desc mb-10px"},"*注：根据nginx转发日志的记录来统计次数",-1);function X(e){return"function"==typeof e||"[object Object]"===Object.prototype.toString.call(e)&&!O(e)}const Y=_({__name:"index",setup(a){const{t:l}=u(),o=m({data:[]}),{loading:s,setLoading:_}=r(),f=async()=>{try{_(!0);const{res:t}=await e.post("/nginx/get_tcp_load_balance"),{tcp_load_balance:a}=t;o.data=Object.entries(a).map((([e,t])=>({load_balance_name:e,...t})))}finally{_(!1)}},w=m({show:!1,title:"编辑端口转发",data:{row:{},callback:f}}),x=e=>Object.keys(e.node_address_map)[0],y=new Map([["tcp","TCP"],["udp","UDP"],["tcp/udp","TCP/UDP"]]),k=new Map([["0.0.0.0","".concat(l("Port.IpOption.1"))],["127.0.0.1","".concat(l("Port.IpOption.0"))]]),U=b([{key:"listen_port",title:"".concat(l("Port.List.Table.Port")),width:"6%",minWidth:100,align:"center"},{key:"count",title:"".concat(l("Port.List.Table.Count")),width:"5%",minWidth:40,render:e=>h(L,{bordered:!1,type:e.count>0?"success":"",size:"small"},{default:()=>[e.count]})},{key:"protocol",title:"".concat(l("Port.List.Table.Protocol")),width:"6%",minWidth:40,render:e=>y.get(e.protocol)},{key:"listen_address",title:"".concat(l("Port.List.Table.Listen")),width:"18%",minWidth:70,render:e=>k.get(e.listen_address)},{key:"node_address",title:"".concat(l("Port.List.Table.NodeAdd")),width:"10%",minWidth:80,render:e=>{const t=x(e);return e.node_address_map[t].node_address}},{key:"node_port",title:"".concat(l("Port.List.Table.NodePort")),width:"8%",minWidth:70,render:e=>{const t=x(e);return e.node_address_map[t].node_port}},{key:"ps",title:"".concat(l("Port.List.Table.Ps")),width:"12%",minWidth:50,render:e=>{const t=x(e);return e.node_address_map[t].ps||"-"}},{key:"action",title:"".concat(l("Public.Table.Action")),width:"10%",minWidth:140,render:e=>{let t,a;return h(T,null,[h(i,{onClick:()=>{O(e)},disabled:0===e.count},X(t=l("Public.Btn.ClearHit"))?t:{default:()=>[t]}),h(i,{style:{marginLeft:"10px"},onClick:()=>{F(e)}},X(a=l("Public.Btn.Del"))?a:{default:()=>[a]})])}}]),O=a=>{n({title:"".concat(l("Port.List.OnEmpty.Title")),content:"".concat(l("Port.List.OnEmpty.Content",{address:a.listen_address,port:a.listen_port})),onConfirm:async()=>{var l;await(l={load_balance_name:a.load_balance_name},e.post("/nginx/clear_tcp_load_balance_count",l,{requestOptions:{loading:t.global.t("Api.Port.Clear"),globalSuccessMessage:!0}})),f()}})},F=async a=>{n({title:"".concat(l("Port.List.OnDel.Title")," -【").concat(a.listen_address,":").concat(a.listen_port,"】"),content:"".concat(l("Port.List.OnDel.Content",{port:a.listen_port})),maxWidth:500,onConfirm:async()=>{var l;await(l={load_balance_name:a.load_balance_name,is_del_port:!0,port:a.listen_port},e.post("/nginx/del_tcp_load_balance",l,{requestOptions:{loading:t.global.t("Api.Port.Del"),globalSuccessMessage:!0}})),f()}})};return f(),(e,t)=>{const a=c,l=d,n=p;return v(),C("div",Q,[h(S,{onRefresh:f}),h(l,{title:e.$t("Port.List.Title")},{default:P((()=>[V,h(a,{loading:g(s),data:g(o).data,columns:g(U)},null,8,["loading","data","columns"])])),_:1},8,["title"]),h(n,{show:g(w).show,"onUpdate:show":t[0]||(t[0]=e=>g(w).show=e),title:g(w).title,"is-footer":!0,component:K,data:g(w).data,"transform-origin":"mouse"},null,8,["show","title","data"])])}}});export{Y as default};
