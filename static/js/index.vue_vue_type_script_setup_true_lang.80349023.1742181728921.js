import{T as s,x as a}from"./index.fc641b56.1742181728921.js";import{d as e,W as l,c as o,S as r,U as n,$ as t,P as i,f as c,O as u,o as p}from"./vue.314199b7.1742181728921.js";const m={class:"leading-[16px] mr-2px"},b=e({__name:"index",props:{status:{}},emits:["click"],setup(e,{emit:b}){const v=e,{t:d}=l(),x=s(),f=new Map([[1,{label:d("Public.Table.Enable"),icon:"run",color:x.value.primaryColor}],[0,{label:d("Public.Table.Disable"),icon:"pause",color:x.value.errorColor}]]),g=o((()=>{var s;const{status:a}=v;return(null==(s=f.get(a))?void 0:s.icon)||""}));return(s,e)=>{var l,o;const v=a;return p(),r("div",{class:"inline-flex items-center cursor-pointer h-[16px] cursor-pointer",style:u({color:null==(l=i(f).get(s.status))?void 0:l.color}),onClick:e[0]||(e[0]=s=>{b("click",s)})},[n("span",m,t((null==(o=i(f).get(s.status))?void 0:o.label)||"--"),1),c(v,{name:i(g),size:"12"},null,8,["name"])],4)}}});export{b as _};
