import { neon } from '@neondatabase/serverless';

const OWNER_PHONE = '9082590422';
const OWNER_EMAIL = 'irshadkhan8879920195@gmail.com';
const DEFAULT_WHATSAPP = '919324793621';
const CATEGORIES = new Set(['silai','kapde','khana','decor']);
const encoder = new TextEncoder();

function json(data, status=200, headers={}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', ...headers } });
}
function cleanPhone(value) { return String(value ?? '').replace(/\D/g,''); }
function validPhone(value) { return /^\d{10}$/.test(value); }
function bodyString(value, max) { return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max; }
function db(env) {
  if (!env.DATABASE_URL) throw new Error('DATABASE_SETUP_REQUIRED');
  return neon(env.DATABASE_URL);
}
function query(env, text, params=[]) {
  return db(env).query(text, params);
}
function missingConfig(env, names) { return names.filter(name => !env[name]); }
function b64url(bytes) { let raw=''; for (const b of bytes) raw += String.fromCharCode(b); return btoa(raw).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function fromB64url(value) { const base=value.replace(/-/g,'+').replace(/_/g,'/'); const padded=base+'='.repeat((4-base.length%4)%4); const raw=atob(padded); return Uint8Array.from(raw,c=>c.charCodeAt(0)); }
async function hmacKey(secret) { return crypto.subtle.importKey('raw', encoder.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign','verify']); }
async function createSession(env, owner) {
  const missing=missingConfig(env,['SESSION_SECRET']); if(missing.length || env.SESSION_SECRET.length<32) throw new Error('SESSION_SETUP_REQUIRED');
  const payload={sub:String(owner.id), phone:owner.phone, exp:Math.floor(Date.now()/1000)+60*60*24*7};
  const encoded=b64url(encoder.encode(JSON.stringify(payload)));
  const sig=await crypto.subtle.sign('HMAC',await hmacKey(env.SESSION_SECRET),encoder.encode(encoded));
  return `${encoded}.${b64url(new Uint8Array(sig))}`;
}
function cookie(request,name) { const header=request.headers.get('Cookie')||''; const match=header.split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'=')); return match ? decodeURIComponent(match.slice(name.length+1)) : ''; }
async function currentOwner(request,env) {
  if(!env.SESSION_SECRET || env.SESSION_SECRET.length<32) return null;
  const token=cookie(request,'__Host-khs_session'); if(!token) return null;
  const [payloadPart,signaturePart,...extra]=token.split('.'); if(!payloadPart||!signaturePart||extra.length) return null;
  try {
    const ok=await crypto.subtle.verify('HMAC',await hmacKey(env.SESSION_SECRET),fromB64url(signaturePart),encoder.encode(payloadPart)); if(!ok)return null;
    const payload=JSON.parse(new TextDecoder().decode(fromB64url(payloadPart))); if(!payload.exp || payload.exp < Date.now()/1000)return null;
    const rows=await query(env,'SELECT id, phone, email, whatsapp_phone, is_primary FROM owners WHERE id = $1 AND phone = $2 AND is_active = TRUE',[payload.sub,payload.phone]);
    return rows[0]||null;
  } catch (_) { return null; }
}
async function requireOwner(request,env) { const owner=await currentOwner(request,env); return owner ? {owner} : {response:json({error:'Please sign in as a store owner first.'},401)}; }
function sameSite(request) {
  const origin=request.headers.get('Origin');
  if(!origin) return true;
  try { return new URL(origin).origin === new URL(request.url).origin; } catch (_) { return false; }
}
function cookieHeader(token,maxAge=604800) { return `__Host-khs_session=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`; }
function ownerView(owner) { return {id:owner.id,phone:owner.phone,email:owner.email||null,whatsapp_phone:owner.whatsapp_phone||null,is_primary:owner.is_primary}; }
async function passwordMatches(candidate,expected) {
  const [candidateHash,expectedHash]=await Promise.all([
    crypto.subtle.digest('SHA-256',encoder.encode(candidate)),
    crypto.subtle.digest('SHA-256',encoder.encode(expected))
  ]);
  const a=new Uint8Array(candidateHash),b=new Uint8Array(expectedHash);let difference=0;
  for(let i=0;i<a.length;i++)difference|=a[i]^b[i];
  return difference===0;
}
async function authLogin(request,env) {
  if(!env.DATABASE_URL)return json({error:'Database-backed owner sign-in and store data are unavailable until PostgreSQL is configured.'},503);
  if(!env.OWNER_PANEL_PASSWORD)return json({error:'The store-owner password is not configured yet.'},503);
  if(!env.SESSION_SECRET||env.SESSION_SECRET.length<32)return json({error:'Store-owner session security is not configured yet.'},503);
  let body;try{body=await request.json();}catch(_){return json({error:'Enter your registered mobile number and password.'},400);}
  const phone=cleanPhone(body.phone),password=body.password;
  if(!validPhone(phone)||typeof password!=='string'||password.length<1||encoder.encode(password).length>256)return json({error:'Enter a valid 10-digit mobile number and password.'},400);
  try {
    const ip=request.headers.get('CF-Connecting-IP')||request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()||'unknown';
    const ipHash=b64url(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(ip))));
    const [phoneAttempts,ipAttempts]=await Promise.all([
      query(env,"SELECT COUNT(*)::int AS count FROM owner_login_attempts WHERE phone = $1 AND created_at > NOW() - INTERVAL '15 minutes'",[phone]),
      query(env,"SELECT COUNT(*)::int AS count FROM owner_login_attempts WHERE ip_hash = $1 AND created_at > NOW() - INTERVAL '15 minutes'",[ipHash])
    ]);
    if(Number(phoneAttempts[0]?.count||0)>=5||Number(ipAttempts[0]?.count||0)>=25)return json({error:'Too many sign-in attempts. Please try again in 15 minutes.'},429);
    await query(env,'INSERT INTO owner_login_attempts (phone, ip_hash, created_at) VALUES ($1, $2, NOW())',[phone,ipHash]);
    await query(env,"DELETE FROM owner_login_attempts WHERE created_at < NOW() - INTERVAL '7 days'");
    if(!await passwordMatches(password,env.OWNER_PANEL_PASSWORD))return json({error:'The mobile number or password is incorrect.'},401);
    const owners=await query(env,'SELECT id, phone, email, whatsapp_phone, is_primary FROM owners WHERE phone = $1 AND is_active = TRUE',[phone]);
    const owner=owners[0];if(!owner)return json({error:'The mobile number or password is incorrect.'},401);
    const token=await createSession(env,owner);
    return json({ok:true,owner:ownerView(owner)},200,{'Set-Cookie':cookieHeader(token)});
  }catch(e){console.error('Owner sign-in failed',String(e).slice(0,180));return json({error:'Store-owner sign-in is temporarily unavailable.'},503);}
}
function validProductBody(body,partial=false) {
  if(!body || typeof body!=='object')return 'Enter product information in a valid format.';
  if(!partial || body.name!==undefined) if(!bodyString(body.name,100)||body.name.trim().length<2)return 'Product name must be between 2 and 100 characters.';
  if(!partial || body.category!==undefined) if(!CATEGORIES.has(body.category))return 'Please choose a product category.';
  if(!partial || body.price!==undefined) if(!Number.isFinite(Number(body.price))||Number(body.price)<0.01||Number(body.price)>10000000)return 'Enter a valid price.';
  if(!partial || body.description!==undefined) if(typeof body.description!=='string'||body.description.trim().length>1000||( !partial && !body.description.trim()))return 'Description must be 1,000 characters or fewer.';
  if(body.in_stock!==undefined && typeof body.in_stock!=='boolean')return 'Invalid product availability setting.';
  if(body.image_key!==undefined && body.image_key!==null && (typeof body.image_key!=='string'||!/^products\/[a-f0-9-]{36}\.(?:jpg|png|webp|avif)$/.test(body.image_key)))return 'Invalid product image format.';
  return null;
}
function productView(p) { return {...p,price:Number(p.price),image_url:p.image_key?`/api/images/${encodeURIComponent(p.image_key)}`:null}; }
async function listProducts(env) {
  try {const rows=await query(env,'SELECT id, name, category, price, description, image AS image_key, in_stock, is_active, owner_id, created_at FROM products WHERE is_active = TRUE ORDER BY created_at DESC');return json({products:rows.map(productView)});}
  catch(e){if(e.message==='DATABASE_SETUP_REQUIRED')return json({error:'Product information is not available yet.'},503);throw e;}
}
async function ownerProducts(request,env) {
  const auth=await requireOwner(request,env);if(auth.response)return auth.response;
  const {owner}=auth;
  const rows=owner.is_primary
    ? await query(env,'SELECT id,name,category,price,description,image AS image_key,in_stock,is_active,owner_id,created_at FROM products ORDER BY created_at DESC')
    : await query(env,'SELECT id,name,category,price,description,image AS image_key,in_stock,is_active,owner_id,created_at FROM products WHERE owner_id = $1 ORDER BY created_at DESC',[owner.id]);
  return json({products:rows.map(productView)});
}
async function createProduct(request,env,owner) {
  let body;try{body=await request.json();}catch(_){return json({error:'Enter product information in a valid format.'},400);}
  const err=validProductBody(body);if(err)return json({error:err},400);
  const rows=await query(env,'INSERT INTO products (name, category, price, description, image, in_stock, owner_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,category,price,description,image AS image_key,in_stock,is_active,owner_id,created_at',[body.name.trim(),body.category,Number(body.price),body.description.trim(),body.image_key||null,body.in_stock!==false,owner.id]);
  return json({product:productView(rows[0])},201);
}
async function updateProduct(request,env,owner,id) {
  let body;try{body=await request.json();}catch(_){return json({error:'Enter product information in a valid format.'},400);}
  const err=validProductBody(body,true);if(err)return json({error:err},400);
  const existing=await query(env,owner.is_primary?'SELECT *, image AS image_key FROM products WHERE id = $1':'SELECT *, image AS image_key FROM products WHERE id = $1 AND owner_id = $2',owner.is_primary?[id]:[id,owner.id]);
  if(!existing[0])return json({error:'Product not found.'},404);
  const old=existing[0];
  const values=[body.name===undefined?old.name:String(body.name).trim(),body.category===undefined?old.category:body.category,body.price===undefined?old.price:Number(body.price),body.description===undefined?old.description:String(body.description).trim(),body.image_key===undefined?old.image_key:body.image_key,body.in_stock===undefined?old.in_stock:body.in_stock,id];
  const rows=await query(env,'UPDATE products SET name=$1, category=$2, price=$3, description=$4, image=$5, in_stock=$6, updated_at=NOW() WHERE id=$7 RETURNING id,name,category,price,description,image AS image_key,in_stock,is_active,owner_id,created_at',values);
  return json({product:productView(rows[0])});
}
async function archiveProduct(env,owner,id) {
  const rows=await query(env,owner.is_primary?'UPDATE products SET is_active=NOT is_active, updated_at=NOW() WHERE id=$1 RETURNING id,is_active':'UPDATE products SET is_active=NOT is_active, updated_at=NOW() WHERE id=$1 AND owner_id=$2 RETURNING id,is_active',owner.is_primary?[id]:[id,owner.id]);
  if(!rows[0])return json({error:'Product not found.'},404);
  return json({ok:true,is_active:rows[0].is_active});
}
async function ordersList(env,owner) {
  const rows=owner.is_primary
    ? await query(env,'SELECT id,product_id,product_name,unit_price,quantity,buyer_name,city,owner_id,created_at FROM orders ORDER BY created_at DESC LIMIT 500')
    : await query(env,'SELECT id,product_id,product_name,unit_price,quantity,buyer_name,city,owner_id,created_at FROM orders WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 500',[owner.id]);
  return json({orders:rows});
}
function waNumber(value) { const d=cleanPhone(value); if(d.length===10)return '91'+d; if(d.length>=11&&d.length<=15)return d; return DEFAULT_WHATSAPP; }
async function sendOrderEmail(env,order,product,ownerWhatsapp,link) {
  if(!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL)return false;
  try {
    const recipients=await query(env,'SELECT email FROM owners WHERE is_primary=TRUE AND is_active=TRUE LIMIT 1');
    const to=recipients[0]?.email||OWNER_EMAIL;
    const text=`New order – Khan Homemade Store\n\nProduct: ${product.name}\nPrice: ₹${product.price}\nQuantity: ${order.quantity}\nCustomer: ${order.buyer_name}\nCity: ${order.city}\nWhatsApp: https://wa.me/${ownerWhatsapp}\nProduct page: ${link}\nOrder ID: ${order.id}`;
    const response=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:env.RESEND_FROM_EMAIL,to:[to],subject:`New order: ${product.name}`,text})});
    return response.ok;
  }catch(_){return false;}
}
async function createOrder(request,env) {
  let body;try{body=await request.json();}catch(_){return json({error:'Enter order information in a valid format.'},400);}
  const productId=String(body.product_id||'');
  if(!/^\d{1,18}$/.test(productId))return json({error:'Invalid product.'},400);
  const name=typeof body.buyer_name==='string'?body.buyer_name.trim():'';
  const city=typeof body.city==='string'?body.city.trim():'';
  const quantity=Number(body.quantity);
  if(!bodyString(name,80)||name.length<2)return json({error:'Name must be between 2 and 80 characters.'},400);
  if(!bodyString(city,80)||city.length<2)return json({error:'City must be between 2 and 80 characters.'},400);
  if(!Number.isInteger(quantity)||quantity<1||quantity>99)return json({error:'Quantity must be between 1 and 99.'},400);
  const rows=await query(env,'INSERT INTO orders (product_id,product_name,unit_price,quantity,buyer_name,city,owner_id) SELECT p.id,p.name,p.price,$2,$3,$4,p.owner_id FROM products p WHERE p.id=$1 AND p.is_active=TRUE AND p.in_stock=TRUE RETURNING id,product_id,product_name,unit_price,quantity,buyer_name,city,owner_id,created_at',[productId,quantity,name,city]);
  if(!rows[0]){const existing=await query(env,'SELECT in_stock,is_active FROM products WHERE id=$1',[productId]);return existing[0]&&existing[0].is_active&&existing[0].in_stock===false?json({error:'This product is not available right now.'},409):json({error:'Product not found or no longer available.'},404);}
  const order=rows[0];
  const owners=await query(env,'SELECT whatsapp_phone FROM owners WHERE id=$1',[order.owner_id]);
  const target=waNumber(owners[0]?.whatsapp_phone||DEFAULT_WHATSAPP);
  const link=new URL(`/#product/${order.product_id}`,request.url).toString();
  const message=`Hello! I’ve placed this order with Khan Homemade Store.\n\nProduct: ${order.product_name}\nPrice: ₹${order.unit_price}\nQuantity: ${order.quantity}\nName: ${order.buyer_name}\nCity: ${order.city}\nProduct link: ${link}`;
  const emailSent=await sendOrderEmail(env,order,{name:order.product_name,price:order.unit_price},target,link);
  return json({ok:true,order_id:order.id,whatsapp_url:`https://wa.me/${target}?text=${encodeURIComponent(message)}`,email_sent:emailSent},201);
}
async function uploadImage(request,env) {
  if(!env.PRODUCT_IMAGES)return json({error:'Product image storage is not available yet.'},503);
  let form;try{form=await request.formData();}catch(_){return json({error:'The image could not be uploaded.'},400);}
  const file=form.get('image');
  if(!file||typeof file.arrayBuffer!=='function')return json({error:'Choose an image file.'},400);
  if(file.size<1||file.size>5*1024*1024)return json({error:'The image must be smaller than 5 MB.'},413);
  const allowed={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/avif':'avif'};
  const ext=allowed[file.type]; if(!ext)return json({error:'Upload a JPG, PNG, WebP, or AVIF image.'},415);
  const bytes=new Uint8Array(await file.arrayBuffer());
  const signature=ext==='jpg'?bytes[0]===0xff&&bytes[1]===0xd8:ext==='png'?bytes[0]===0x89&&bytes[1]===0x50&&bytes[2]===0x4e&&bytes[3]===0x47:ext==='webp'?String.fromCharCode(...bytes.slice(0,4))==='RIFF'&&String.fromCharCode(...bytes.slice(8,12))==='WEBP':String.fromCharCode(...bytes.slice(4,12)).includes('ftypavif');
  if(!signature)return json({error:'The image file format is invalid.'},415);
  const key=`products/${crypto.randomUUID()}.${ext}`;
  await env.PRODUCT_IMAGES.put(key,bytes,{httpMetadata:{contentType:file.type,cacheControl:'public, max-age=86400'}});
  return json({image_key:key,url:`/api/images/${encodeURIComponent(key)}`},201);
}
async function serveImage(request,env,key) {
  if(!/^products\/[a-f0-9-]{36}\.(?:jpg|png|webp|avif)$/.test(key))return json({error:'Image not found.'},404);
  if(!env.PRODUCT_IMAGES)return json({error:'Image storage is not available yet.'},503);
  const object=await env.PRODUCT_IMAGES.get(key);if(!object)return json({error:'Image not found.'},404);
  const headers=new Headers();object.writeHttpMetadata(headers);headers.set('etag',object.httpEtag);headers.set('Cache-Control','public, max-age=86400');headers.set('X-Content-Type-Options','nosniff');
  return new Response(object.body,{headers});
}
async function ownersList(env) { const rows=await query(env,'SELECT id,phone,email,whatsapp_phone,is_primary,is_active,created_at FROM owners ORDER BY is_primary DESC,created_at ASC');return json({owners:rows}); }
async function addOwner(request,env) {
  let body;try{body=await request.json();}catch(_){return json({error:'Enter store-owner information in a valid format.'},400);}
  const phone=cleanPhone(body.phone),whatsapp=body.whatsapp_phone?cleanPhone(body.whatsapp_phone):null;
  if(!validPhone(phone))return json({error:'The owner’s mobile number must have 10 digits.'},400);
  if(phone===OWNER_PHONE)return json({error:'This is already the primary owner’s number.'},409);
  if(whatsapp && (whatsapp.length<10||whatsapp.length>15))return json({error:'The WhatsApp number must have 10 to 15 digits.'},400);
  const found=await query(env,'SELECT id,is_active FROM owners WHERE phone=$1',[phone]);
  if(found[0]){if(found[0].is_active)return json({error:'An owner with this number already exists.'},409);const rows=await query(env,'UPDATE owners SET is_active=TRUE,whatsapp_phone=$1 WHERE id=$2 RETURNING id,phone,email,whatsapp_phone,is_primary,is_active',[whatsapp,found[0].id]);return json({owner:rows[0]},201);}
  const rows=await query(env,'INSERT INTO owners (phone,whatsapp_phone,is_primary,is_active) VALUES ($1,$2,FALSE,TRUE) RETURNING id,phone,email,whatsapp_phone,is_primary,is_active',[phone,whatsapp]);return json({owner:rows[0]},201);
}
async function removeOwner(env,id) {
  const rows=await query(env,'UPDATE owners SET is_active=FALSE WHERE id=$1 AND is_primary=FALSE RETURNING id',[id]);
  if(!rows[0])return json({error:'Owner not found, or the primary owner cannot be removed.'},404);
  return json({ok:true});
}
async function routeApi(request,env) {
  const url=new URL(request.url),path=url.pathname,method=request.method;
  if(!sameSite(request))return json({error:'This request was not accepted.'},403);
  if(method==='GET'&&path==='/api/health')return json({ok:true,service:'khan-homemade-store'});
  if(method==='GET'&&path==='/api/products')return listProducts(env);
  if(method==='POST'&&path==='/api/auth/login')return authLogin(request,env);
  if(method==='POST'&&path==='/api/auth/logout')return json({ok:true},200,{'Set-Cookie':cookieHeader('',0)});
  if(method==='POST'&&path==='/api/orders')return createOrder(request,env);
  const imageMatch=path.match(/^\/api\/images\/(.+)$/); if(method==='GET'&&imageMatch)return serveImage(request,env,decodeURIComponent(imageMatch[1]));
  const auth=await requireOwner(request,env);if(auth.response)return auth.response;
  if(method==='GET'&&path==='/api/owner/me')return json({owner:ownerView(auth.owner)});
  if(method==='GET'&&path==='/api/owner/products')return ownerProducts(request,env);
  if(method==='POST'&&path==='/api/owner/products')return createProduct(request,env,auth.owner);
  if(method==='GET'&&path==='/api/owner/orders')return ordersList(env,auth.owner);
  if(method==='POST'&&path==='/api/owner/images')return uploadImage(request,env);
  if(path==='/api/owner/owners'){
    if(!auth.owner.is_primary)return json({error:'Only the primary owner can manage other owners.'},403);
    if(method==='GET')return ownersList(env); if(method==='POST')return addOwner(request,env);
  }
  const productMatch=path.match(/^\/api\/owner\/products\/(\d+)$/);
  if(productMatch){const id=productMatch[1];if(method==='PUT')return updateProduct(request,env,auth.owner,id);if(method==='DELETE')return archiveProduct(env,auth.owner,id);}
  const ownerMatch=path.match(/^\/api\/owner\/owners\/(\d+)$/);
  if(ownerMatch&&method==='DELETE'){if(!auth.owner.is_primary)return json({error:'Only the primary owner can manage other owners.'},403);return removeOwner(env,ownerMatch[1]);}
  return json({error:'This request is not available.'},404);
}

export default {
  async fetch(request,env,ctx) {
    const url=new URL(request.url);
    if(url.pathname.startsWith('/api/')) {
      try { return await routeApi(request,env); }
      catch(e) {
        if(e.message==='DATABASE_SETUP_REQUIRED')return json({error:'Product information is not available yet.'},503);
        if(e.message==='SESSION_SETUP_REQUIRED')return json({error:'Store-owner session security is not configured yet.'},503);
        console.error('API error',String(e).slice(0,220));
        return json({error:'A temporary server error occurred. Please try again in a little while.'},500);
      }
    }
    if(url.pathname==='/robots.txt')return new Response('User-agent: *\nAllow: /\n',{headers:{'Content-Type':'text/plain; charset=utf-8'}});
    return env.ASSETS.fetch(request);
  }
};
