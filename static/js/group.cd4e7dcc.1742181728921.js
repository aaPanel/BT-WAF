import{cI as s,i as t}from"./index.fc641b56.1742181728921.js";const e=()=>s.post("/inset/ip_list"),i=e=>s.post("/inset/set_ip_group",e,{requestOptions:{loading:t.global.t("Api.Group.Add"),globalSuccessMessage:!0}}),o=e=>s.post("/inset/edit_ip_group",e,{requestOptions:{loading:t.global.t("Api.Group.Edit"),globalSuccessMessage:!0}}),p=e=>s.post("/inset/del_ip_group",e,{requestOptions:{loading:t.global.t("Api.Group.Del"),globalSuccessMessage:!0}}),a=()=>s.post("/inset/ip_name_list"),l=t=>s.post("/inset/get_by_name_ip",t),g=t=>s.post("/inset/get_malicious_ip_list",t);export{l as a,g as b,e as c,p as d,o as e,a as g,i as s};
