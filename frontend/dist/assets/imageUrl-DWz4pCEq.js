const s="http://localhost:8100",r=t=>t?t.startsWith("http://")||t.startsWith("https://")?t:t.startsWith("/static/")?`${s}${t}`:t:"";export{r};
