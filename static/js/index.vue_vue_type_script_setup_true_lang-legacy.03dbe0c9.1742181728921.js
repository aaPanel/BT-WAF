System.register(["./index-legacy.b0161ddd.1742181728921.js","./vue-legacy.fb39cc53.1742181728921.js"],(function(e,n){"use strict";var l,t,i,r,o,c,u,s,a,v,p,d;return{setters:[function(e){l=e.T,t=e.x},function(e){i=e.d,r=e.W,o=e.c,c=e.S,u=e.U,s=e.$,a=e.P,v=e.f,p=e.O,d=e.o}],execute:function(){var n={class:"leading-[16px] mr-2px"};e("_",i({__name:"index",props:{status:{}},emits:["click"],setup:function(e,i){var f=i.emit,b=e,m=r().t,x=l(),g=new Map([[1,{label:m("Public.Table.Enable"),icon:"run",color:x.value.primaryColor}],[0,{label:m("Public.Table.Disable"),icon:"pause",color:x.value.errorColor}]]),y=o((function(){var e,n=b.status;return(null===(e=g.get(n))||void 0===e?void 0:e.icon)||""}));return function(e,l){var i,r,o=t;return d(),c("div",{class:"inline-flex items-center cursor-pointer h-[16px] cursor-pointer",style:p({color:null===(i=a(g).get(e.status))||void 0===i?void 0:i.color}),onClick:l[0]||(l[0]=function(e){f("click",e)})},[u("span",n,s((null===(r=a(g).get(e.status))||void 0===r?void 0:r.label)||"--"),1),v(o,{name:a(y),size:"12"},null,8,["name"])],4)}}}))}}}));
