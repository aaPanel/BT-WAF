const t={default:"ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz123456789",password:"AaBbCcDdEeFfGgHhIiJjKkLlMmNnPpRrTtSsWwXxTyZz12345678"},a=(a=10,r="default")=>{let s="";const e=t[r];for(let t=0;t<a;t++)s+=e.charAt(Math.floor(Math.random()*e.length));return s},r=(t=16)=>a(t,"password");export{r as a,a as g};
