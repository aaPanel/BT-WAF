import{e6 as e,B as n,K as r,D as a,F as o,G as t,P as l,e8 as s,dd as i}from"./index.fc641b56.1742181728921.js";import{d,c as u,h as c,J as p,F as m,ak as g,r as h,G as v,w as b,b as f,P as y,ad as k,o as S,f as w,A as x}from"./vue.314199b7.1742181728921.js";import{b as z}from"./DataTable.762c357a.1742181728921.js";let B=!1;const P={name:"Skeleton",common:n,self:e=>{const{heightSmall:n,heightMedium:r,heightLarge:a,borderRadius:o}=e;return{color:"#eee",colorEnd:"#ddd",borderRadius:o,heightSmall:n,heightMedium:r,heightLarge:a}}},C=r([a("skeleton","\n height: 1em;\n width: 100%;\n transition: background-color .3s var(--n-bezier);\n transition:\n --n-color-start .3s var(--n-bezier),\n --n-color-end .3s var(--n-bezier),\n background-color .3s var(--n-bezier);\n animation: 2s skeleton-loading infinite cubic-bezier(0.36, 0, 0.64, 1);\n background-color: var(--n-color-start);\n "),r("@keyframes skeleton-loading","\n 0% {\n background: var(--n-color-start);\n }\n 40% {\n background: var(--n-color-end);\n }\n 80% {\n background: var(--n-color-start);\n }\n 100% {\n background: var(--n-color-start);\n }\n ")]),j=d({name:"Skeleton",inheritAttrs:!1,props:Object.assign(Object.assign({},t.props),{text:Boolean,round:Boolean,circle:Boolean,height:[String,Number],width:[String,Number],size:String,repeat:{type:Number,default:1},animated:{type:Boolean,default:!0},sharp:{type:Boolean,default:!0}}),setup(n){!function(){if(e&&window.CSS&&!B&&(B=!0,"registerProperty"in(null===window||void 0===window?void 0:window.CSS)))try{CSS.registerProperty({name:"--n-color-start",syntax:"<color>",inherits:!1,initialValue:"#0000"}),CSS.registerProperty({name:"--n-color-end",syntax:"<color>",inherits:!1,initialValue:"#0000"})}catch(n){}}();const{mergedClsPrefixRef:r}=o(n),a=t("Skeleton","-skeleton",C,P,n,r);return{mergedClsPrefix:r,style:u((()=>{var e,r;const o=a.value,{common:{cubicBezierEaseInOut:t}}=o,i=o.self,{color:d,colorEnd:u,borderRadius:c}=i;let p;const{circle:m,sharp:g,round:h,width:v,height:b,size:f,text:y,animated:k}=n;void 0!==f&&(p=i[l("height",f)]);const S=m?null!==(e=null!=v?v:b)&&void 0!==e?e:p:v,w=null!==(r=m&&null!=v?v:b)&&void 0!==r?r:p;return{display:y?"inline-block":"",verticalAlign:y?"-0.125em":"",borderRadius:m?"50%":h?"4096px":g?"":c,width:"number"==typeof S?s(S):S,height:"number"==typeof w?s(w):w,animation:k?"":"none","--n-bezier":t,"--n-color-start":d,"--n-color-end":u}}))}},render(){const{repeat:e,style:n,mergedClsPrefix:r,$attrs:a}=this,o=c("div",p({class:"".concat(r,"-skeleton"),style:n},a));return e>1?c(m,null,Array.apply(null,{length:e}).map((e=>[o,"\n"]))):o}}),E=e=>i.cloneDeep(e),R=d({__name:"index",props:{data:{default:()=>[]},loading:{type:Boolean,default:!1},columns:{default:()=>[]}},setup(e){const n=e,{columns:r,data:a,loading:o}=g(n),t=()=>E(k(r.value)),l=h(t()),s=h(t()),i=h([]);let d=!1;return v((()=>{var e;if(o.value){if(d=!0,l.value.forEach((e=>{e.ellipsis=void 0,e.render=()=>w(j,null,null),"selection"===e.type&&(e.type=void 0)})),0===(null==(e=a.value)?void 0:e.length))for(let n=0;n<10;n++)i.value.push({})}else i.value=[],l.value.forEach(((e,n)=>{const r=s.value[n];e.type=r.type,e.ellipsis=r.ellipsis,e.render=r.render})),x((()=>{i.value=a.value||[],d=!1}))})),b((()=>a.value),(e=>{d||(i.value=e||[])}),{deep:!0}),(e,n)=>{const r=z;return S(),f(r,p(e.$attrs,{bordered:!1,data:y(i),columns:y(l)}),null,16,["data","columns"])}}});export{R as _,E as c};
