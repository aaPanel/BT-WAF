import{B as e,cc as n,D as t,E as a,e9 as o,K as i,L as r,M as l,F as c,G as s,cg as d,ci as u,I as h,ee as b,J as v,e4 as g,dq as p,bs as f,P as w,e8 as m,ds as x}from"./index.fc641b56.1742181728921.js";import{d as y,r as k,z as S,c as C,h as B}from"./vue.314199b7.1742181728921.js";const _={buttonHeightSmall:"14px",buttonHeightMedium:"18px",buttonHeightLarge:"22px",buttonWidthSmall:"14px",buttonWidthMedium:"18px",buttonWidthLarge:"22px",buttonWidthPressedSmall:"20px",buttonWidthPressedMedium:"24px",buttonWidthPressedLarge:"28px",railHeightSmall:"18px",railHeightMedium:"22px",railHeightLarge:"26px",railWidthSmall:"32px",railWidthMedium:"40px",railWidthLarge:"48px"},z={name:"Switch",common:e,self:e=>{const{primaryColor:t,opacityDisabled:a,borderRadius:o,textColor3:i}=e;return Object.assign(Object.assign({},_),{iconColor:i,textColor:"white",loadingColor:t,opacityDisabled:a,railColor:"rgba(0, 0, 0, .14)",railColorActive:t,buttonBoxShadow:"0 1px 4px 0 rgba(0, 0, 0, 0.3), inset 0 0 1px 0 rgba(0, 0, 0, 0.05)",buttonColor:"#FFF",railBorderRadiusSmall:o,railBorderRadiusMedium:o,railBorderRadiusLarge:o,buttonBorderRadiusSmall:o,buttonBorderRadiusMedium:o,buttonBorderRadiusLarge:o,boxShadowFocus:"0 0 0 2px ".concat(n(t,{alpha:.2}))})}},F=t("switch","\n height: var(--n-height);\n min-width: var(--n-width);\n vertical-align: middle;\n user-select: none;\n -webkit-user-select: none;\n display: inline-flex;\n outline: none;\n justify-content: center;\n align-items: center;\n",[a("children-placeholder","\n height: var(--n-rail-height);\n display: flex;\n flex-direction: column;\n overflow: hidden;\n pointer-events: none;\n visibility: hidden;\n "),a("rail-placeholder","\n display: flex;\n flex-wrap: none;\n "),a("button-placeholder","\n width: calc(1.75 * var(--n-rail-height));\n height: var(--n-rail-height);\n "),t("base-loading","\n position: absolute;\n top: 50%;\n left: 50%;\n transform: translateX(-50%) translateY(-50%);\n font-size: calc(var(--n-button-width) - 4px);\n color: var(--n-loading-color);\n transition: color .3s var(--n-bezier);\n ",[o({left:"50%",top:"50%",originalTransform:"translateX(-50%) translateY(-50%)"})]),a("checked, unchecked","\n transition: color .3s var(--n-bezier);\n color: var(--n-text-color);\n box-sizing: border-box;\n position: absolute;\n white-space: nowrap;\n top: 0;\n bottom: 0;\n display: flex;\n align-items: center;\n line-height: 1;\n "),a("checked","\n right: 0;\n padding-right: calc(1.25 * var(--n-rail-height) - var(--n-offset));\n "),a("unchecked","\n left: 0;\n justify-content: flex-end;\n padding-left: calc(1.25 * var(--n-rail-height) - var(--n-offset));\n "),i("&:focus",[a("rail","\n box-shadow: var(--n-box-shadow-focus);\n ")]),r("round",[a("rail","border-radius: calc(var(--n-rail-height) / 2);",[a("button","border-radius: calc(var(--n-button-height) / 2);")])]),l("disabled",[l("icon",[r("rubber-band",[r("pressed",[a("rail",[a("button","max-width: var(--n-button-width-pressed);")])]),a("rail",[i("&:active",[a("button","max-width: var(--n-button-width-pressed);")])]),r("active",[r("pressed",[a("rail",[a("button","left: calc(100% - var(--n-offset) - var(--n-button-width-pressed));")])]),a("rail",[i("&:active",[a("button","left: calc(100% - var(--n-offset) - var(--n-button-width-pressed));")])])])])])]),r("active",[a("rail",[a("button","left: calc(100% - var(--n-button-width) - var(--n-offset))")])]),a("rail","\n overflow: hidden;\n height: var(--n-rail-height);\n min-width: var(--n-rail-width);\n border-radius: var(--n-rail-border-radius);\n cursor: pointer;\n position: relative;\n transition:\n opacity .3s var(--n-bezier),\n background .3s var(--n-bezier),\n box-shadow .3s var(--n-bezier);\n background-color: var(--n-rail-color);\n ",[a("button-icon","\n color: var(--n-icon-color);\n transition: color .3s var(--n-bezier);\n font-size: calc(var(--n-button-height) - 4px);\n position: absolute;\n left: 0;\n right: 0;\n top: 0;\n bottom: 0;\n display: flex;\n justify-content: center;\n align-items: center;\n line-height: 1;\n ",[o()]),a("button",'\n align-items: center; \n top: var(--n-offset);\n left: var(--n-offset);\n height: var(--n-button-height);\n width: var(--n-button-width-pressed);\n max-width: var(--n-button-width);\n border-radius: var(--n-button-border-radius);\n background-color: var(--n-button-color);\n box-shadow: var(--n-button-box-shadow);\n box-sizing: border-box;\n cursor: inherit;\n content: "";\n position: absolute;\n transition:\n background-color .3s var(--n-bezier),\n left .3s var(--n-bezier),\n opacity .3s var(--n-bezier),\n max-width .3s var(--n-bezier),\n box-shadow .3s var(--n-bezier);\n ')]),r("active",[a("rail","background-color: var(--n-rail-color-active);")]),r("loading",[a("rail","\n cursor: wait;\n ")]),r("disabled",[a("rail","\n cursor: not-allowed;\n opacity: .5;\n ")])]);let R;const V=y({name:"Switch",props:Object.assign(Object.assign({},s.props),{size:{type:String,default:"medium"},value:{type:[String,Number,Boolean],default:void 0},loading:Boolean,defaultValue:{type:[String,Number,Boolean],default:!1},disabled:{type:Boolean,default:void 0},round:{type:Boolean,default:!0},"onUpdate:value":[Function,Array],onUpdateValue:[Function,Array],checkedValue:{type:[String,Number,Boolean],default:!0},uncheckedValue:{type:[String,Number,Boolean],default:!1},railStyle:Function,rubberBand:{type:Boolean,default:!0},onChange:[Function,Array]}),setup(e){void 0===R&&(R="undefined"==typeof CSS||void 0!==CSS.supports&&CSS.supports("width","max(1px)"));const{mergedClsPrefixRef:n,inlineThemeDisabled:t}=c(e),a=s("Switch","-switch",F,z,e,n),o=d(e),{mergedSizeRef:i,mergedDisabledRef:r}=o,l=k(e.defaultValue),b=S(e,"value"),v=u(b,l),g=C((()=>v.value===e.checkedValue)),p=k(!1),y=k(!1),B=C((()=>{const{railStyle:n}=e;if(n)return n({focused:y.value,checked:g.value})}));function _(n){const{"onUpdate:value":t,onChange:a,onUpdateValue:i}=e,{nTriggerFormInput:r,nTriggerFormChange:c}=o;t&&f(t,n),i&&f(i,n),a&&f(a,n),l.value=n,r(),c()}const V=C((()=>{const{value:e}=i,{self:{opacityDisabled:n,railColor:t,railColorActive:o,buttonBoxShadow:r,buttonColor:l,boxShadowFocus:c,loadingColor:s,textColor:d,iconColor:u,[w("buttonHeight",e)]:h,[w("buttonWidth",e)]:b,[w("buttonWidthPressed",e)]:v,[w("railHeight",e)]:g,[w("railWidth",e)]:p,[w("railBorderRadius",e)]:f,[w("buttonBorderRadius",e)]:y},common:{cubicBezierEaseInOut:k}}=a.value;let S,C,B;return R?(S="calc((".concat(g," - ").concat(h,") / 2)"),C="max(".concat(g,", ").concat(h,")"),B="max(".concat(p,", calc(").concat(p," + ").concat(h," - ").concat(g,"))")):(S=m((x(g)-x(h))/2),C=m(Math.max(x(g),x(h))),B=x(g)>x(h)?p:m(x(p)+x(h)-x(g))),{"--n-bezier":k,"--n-button-border-radius":y,"--n-button-box-shadow":r,"--n-button-color":l,"--n-button-width":b,"--n-button-width-pressed":v,"--n-button-height":h,"--n-height":C,"--n-offset":S,"--n-opacity-disabled":n,"--n-rail-border-radius":f,"--n-rail-color":t,"--n-rail-color-active":o,"--n-rail-height":g,"--n-rail-width":p,"--n-width":B,"--n-box-shadow-focus":c,"--n-loading-color":s,"--n-text-color":d,"--n-icon-color":u}})),W=t?h("switch",C((()=>i.value[0])),V,e):void 0;return{handleClick:function(){e.loading||r.value||(v.value!==e.checkedValue?_(e.checkedValue):_(e.uncheckedValue))},handleBlur:function(){y.value=!1,function(){const{nTriggerFormBlur:e}=o;e()}(),p.value=!1},handleFocus:function(){y.value=!0,function(){const{nTriggerFormFocus:e}=o;e()}()},handleKeyup:function(n){e.loading||r.value||" "===n.key&&(v.value!==e.checkedValue?_(e.checkedValue):_(e.uncheckedValue),p.value=!1)},handleKeydown:function(n){e.loading||r.value||" "===n.key&&(n.preventDefault(),p.value=!0)},mergedRailStyle:B,pressed:p,mergedClsPrefix:n,mergedValue:v,checked:g,mergedDisabled:r,cssVars:t?void 0:V,themeClass:null==W?void 0:W.themeClass,onRender:null==W?void 0:W.onRender}},render(){const{mergedClsPrefix:e,mergedDisabled:n,checked:t,mergedRailStyle:a,onRender:o,$slots:i}=this;null==o||o();const{checked:r,unchecked:l,icon:c,"checked-icon":s,"unchecked-icon":d}=i,u=!(b(c)&&b(s)&&b(d));return B("div",{role:"switch","aria-checked":t,class:["".concat(e,"-switch"),this.themeClass,u&&"".concat(e,"-switch--icon"),t&&"".concat(e,"-switch--active"),n&&"".concat(e,"-switch--disabled"),this.round&&"".concat(e,"-switch--round"),this.loading&&"".concat(e,"-switch--loading"),this.pressed&&"".concat(e,"-switch--pressed"),this.rubberBand&&"".concat(e,"-switch--rubber-band")],tabindex:this.mergedDisabled?void 0:0,style:this.cssVars,onClick:this.handleClick,onFocus:this.handleFocus,onBlur:this.handleBlur,onKeyup:this.handleKeyup,onKeydown:this.handleKeydown},B("div",{class:"".concat(e,"-switch__rail"),"aria-hidden":"true",style:a},v(r,(n=>v(l,(t=>n||t?B("div",{"aria-hidden":!0,class:"".concat(e,"-switch__children-placeholder")},B("div",{class:"".concat(e,"-switch__rail-placeholder")},B("div",{class:"".concat(e,"-switch__button-placeholder")}),n),B("div",{class:"".concat(e,"-switch__rail-placeholder")},B("div",{class:"".concat(e,"-switch__button-placeholder")}),t)):null)))),B("div",{class:"".concat(e,"-switch__button")},v(c,(n=>v(s,(t=>v(d,(a=>B(g,null,{default:()=>this.loading?B(p,{key:"loading",clsPrefix:e,strokeWidth:20}):this.checked&&(t||n)?B("div",{class:"".concat(e,"-switch__button-icon"),key:t?"checked-icon":"icon"},t||n):this.checked||!a&&!n?null:B("div",{class:"".concat(e,"-switch__button-icon"),key:a?"unchecked-icon":"icon"},a||n)}))))))),v(r,(n=>n&&B("div",{key:"checked",class:"".concat(e,"-switch__checked")},n))),v(l,(n=>n&&B("div",{key:"unchecked",class:"".concat(e,"-switch__unchecked")},n))))))}});export{V as N};
