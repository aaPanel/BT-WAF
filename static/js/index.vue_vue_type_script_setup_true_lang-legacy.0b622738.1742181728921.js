System.register(["./index-legacy.b0161ddd.1742181728921.js","./vue-legacy.fb39cc53.1742181728921.js","./DataTable-legacy.ce503b2f.1742181728921.js"],(function(e,n){"use strict";var r,t,o,i,a,l,u,s,c,d,f,v,g,h,p,m,b,y,k,S,w,x,z,B,P;return{setters:[function(e){r=e.e6,t=e.B,o=e.K,i=e.D,a=e.F,l=e.G,u=e.P,s=e.e8,c=e.dd},function(e){d=e.d,f=e.c,v=e.h,g=e.J,h=e.F,p=e.ak,m=e.r,b=e.G,y=e.w,k=e.b,S=e.P,w=e.ad,x=e.o,z=e.f,B=e.A},function(e){P=e.b}],execute:function(){var n=!1,C={name:"Skeleton",common:t,self:function(e){var n=e.heightSmall,r=e.heightMedium,t=e.heightLarge;return{color:"#eee",colorEnd:"#ddd",borderRadius:e.borderRadius,heightSmall:n,heightMedium:r,heightLarge:t}}},j=o([i("skeleton","\n height: 1em;\n width: 100%;\n transition: background-color .3s var(--n-bezier);\n transition:\n --n-color-start .3s var(--n-bezier),\n --n-color-end .3s var(--n-bezier),\n background-color .3s var(--n-bezier);\n animation: 2s skeleton-loading infinite cubic-bezier(0.36, 0, 0.64, 1);\n background-color: var(--n-color-start);\n "),o("@keyframes skeleton-loading","\n 0% {\n background: var(--n-color-start);\n }\n 40% {\n background: var(--n-color-end);\n }\n 80% {\n background: var(--n-color-start);\n }\n 100% {\n background: var(--n-color-start);\n }\n ")]),E=Object.assign(Object.assign({},l.props),{text:Boolean,round:Boolean,circle:Boolean,height:[String,Number],width:[String,Number],size:String,repeat:{type:Number,default:1},animated:{type:Boolean,default:!0},sharp:{type:Boolean,default:!0}}),R=d({name:"Skeleton",inheritAttrs:!1,props:E,setup:function(e){!function(){if(r&&window.CSS&&!n&&(n=!0,"registerProperty"in(null===window||void 0===window?void 0:window.CSS)))try{CSS.registerProperty({name:"--n-color-start",syntax:"<color>",inherits:!1,initialValue:"#0000"}),CSS.registerProperty({name:"--n-color-end",syntax:"<color>",inherits:!1,initialValue:"#0000"})}catch(e){}}();var t=a(e).mergedClsPrefixRef,o=l("Skeleton","-skeleton",j,C,e,t);return{mergedClsPrefix:t,style:f((function(){var n,r,t,i=o.value,a=i.common.cubicBezierEaseInOut,l=i.self,c=l.color,d=l.colorEnd,f=l.borderRadius,v=e.circle,g=e.sharp,h=e.round,p=e.width,m=e.height,b=e.size,y=e.text,k=e.animated;void 0!==b&&(t=l[u("height",b)]);var S=v?null!==(n=null!=p?p:m)&&void 0!==n?n:t:p,w=null!==(r=v&&null!=p?p:m)&&void 0!==r?r:t;return{display:y?"inline-block":"",verticalAlign:y?"-0.125em":"",borderRadius:v?"50%":h?"4096px":g?"":f,width:"number"==typeof S?s(S):S,height:"number"==typeof w?s(w):w,animation:k?"":"none","--n-bezier":a,"--n-color-start":c,"--n-color-end":d}}))}},render:function(){var e=this.repeat,n=this.style,r=this.mergedClsPrefix,t=this.$attrs,o=v("div",g({class:"".concat(r,"-skeleton"),style:n},t));return e>1?v(h,null,Array.apply(null,{length:e}).map((function(e){return[o,"\n"]}))):o}}),A=e("c",(function(e){return c.cloneDeep(e)}));e("_",d({__name:"index",props:{data:{default:function(){return[]}},loading:{type:Boolean,default:!1},columns:{default:function(){return[]}}},setup:function(e){var n=p(e),r=n.columns,t=n.data,o=n.loading,i=function(){return A(w(r.value))},a=m(i()),l=m(i()),u=m([]),s=!1;return b((function(){var e;if(o.value){if(s=!0,a.value.forEach((function(e){e.ellipsis=void 0,e.render=function(){return z(R,null,null)},"selection"===e.type&&(e.type=void 0)})),0===(null===(e=t.value)||void 0===e?void 0:e.length))for(var n=0;n<10;n++)u.value.push({})}else u.value=[],a.value.forEach((function(e,n){var r=l.value[n];e.type=r.type,e.ellipsis=r.ellipsis,e.render=r.render})),B((function(){u.value=t.value||[],s=!1}))})),y((function(){return t.value}),(function(e){s||(u.value=e||[])}),{deep:!0}),function(e,n){var r=P;return x(),k(r,g(e.$attrs,{bordered:!1,data:S(u),columns:S(a)}),null,16,["data","columns"])}}}))}}}));
