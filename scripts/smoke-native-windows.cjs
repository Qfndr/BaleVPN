const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const [base,debug,monitor,exports]=process.argv.slice(2),browser=await chromium.connectOverCDP('http://127.0.0.1:'+debug);
 try{
 let page;for(let i=0;i<100;i++){page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().startsWith(base));if(page)break;await new Promise(r=>setTimeout(r,100));}
 assert.ok(page,'Only attach to the isolated application URL');const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const session=await page.context().newCDPSession(page);await session.send('Emulation.setFocusEmulationEnabled',{enabled:false});
 await page.waitForFunction(()=>_state&&document.documentElement.dataset.desktop==='true');
 await page.waitForFunction(()=>document.getElementById('desktopPreferences').hidden===false);
 assert.equal(await page.evaluate(()=>window.__BALE_DESKTOP__),true);
 let windows=await(await fetch(monitor+'/window')).json();assert.ok(windows.some(w=>w.title==='BaleVPN'&&w.clientInset<24&&!w.visible),JSON.stringify(windows));assert.ok(!windows.some(w=>w.class==='ConsoleWindowClass'));
 assert.ok(await page.locator('#trayUnavailable').isHidden(),'A real tray icon must be available');
 await fetch(base+'/desktop/show',{method:'POST',headers:{Origin:base}});await page.waitForFunction(()=>!_desktopHidden);
 await page.evaluate(()=>{setWorkspaceTab('appearance');document.getElementById('languageSelect').value='fa';document.getElementById('themeSelect').value='dark';applyAppearance();});
 await page.waitForFunction(()=>document.getElementById('nativeTitlebar').getBoundingClientRect().height===48);
 assert.equal(await page.locator('html').getAttribute('dir'),'rtl');assert.ok(await page.locator('#nativeTitlebar').isVisible());
 await page.evaluate(()=>{const field=document.getElementById('alwaysOnTop');field.checked=true;field.dispatchEvent(new Event('change'));});
 await page.waitForFunction(()=>document.getElementById('alwaysOnTop').checked);
 await page.evaluate(()=>{const field=document.getElementById('alwaysOnTop');field.checked=false;field.dispatchEvent(new Event('change'));});
 await page.evaluate(()=>desktopCommand('close'));await page.waitForFunction(()=>_desktopHidden,null,{polling:100});const hidden=await(await fetch(monitor+'/window')).json();assert.ok(hidden.some(w=>w.title==='BaleVPN'&&!w.visible));
 await fetch(base+'/desktop/show',{method:'POST',headers:{Origin:base}});await page.waitForFunction(()=>!_desktopHidden);
 await page.evaluate(()=>setWorkspaceTab('backup'));await page.waitForFunction(()=>document.querySelector('#backupAccounts input[value="0"]'));
 await page.evaluate(()=>{document.querySelector('#backupAccounts input[value="0"]').checked=true;document.getElementById('backupPassword').value='native-fixture-passphrase-123';document.getElementById('backupPasswordConfirm').value='native-fixture-passphrase-123';document.getElementById('backupExport').click();});
 await page.waitForFunction(()=>document.getElementById('backupExportStatus').textContent.includes('ذخیره شد'),null,{timeout:45000});
 assert.equal(await page.locator('#backupPassword').inputValue(),'');assert.equal(await page.locator('#backupPasswordConfirm').inputValue(),'');assert.equal(fs.readdirSync(exports).filter(n=>n.endsWith('.balevault')).length,1);
 const storage=await page.evaluate(()=>JSON.stringify(localStorage));assert.ok(!storage.includes('native-fixture-passphrase'));
 if(process.env.BALEVPN_SCREENSHOTS){fs.mkdirSync(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'native-backup-fa-dark.png')});}
 assert.deepEqual(errors,[]);await page.evaluate(()=>desktopCommand('quit'));console.log('PASS real WebView2/tray IPC, no caption/console, Persian native titlebar, hidden startup, close/show, preferences, native encrypted download, no password storage and quit');
 }finally{await browser.close().catch(()=>{});}
})().catch(e=>{console.error(e);process.exitCode=1;});
