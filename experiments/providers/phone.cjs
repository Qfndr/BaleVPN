const countries=require('./countries.json');
function digits(value){return String(value).replace(/[۰-۹]/g,c=>String(c.charCodeAt(0)-1776)).replace(/[٠-٩]/g,c=>String(c.charCodeAt(0)-1632));}
function normalize(country,value){const c=countries.find(c=>c.iso===country);if(!c||typeof value!=='string')throw new Error('invalid_phone');let n=digits(value).replace(/[\s()-]/g,'');
 if(n.startsWith('00'))n='+'+n.slice(2);
 if(n.startsWith('+')){if(!/^\+[1-9]\d{5,14}$/.test(n)||!n.slice(1).startsWith(c.code))throw new Error('phone_country_mismatch');n=n.slice(c.code.length+1);}
 else if(c.prefix&&n.startsWith(c.prefix)&&n.length>7)n=n.slice(c.prefix.length);
 if(!/^\d{5,14}$/.test(n)||BigInt(n)===0n||c.code.length+n.length>15)throw new Error('invalid_phone');
 return {country:c.iso,nationalNumber:n,internationalNumber:'+'+c.code+n};
}
module.exports={countries,normalize};
