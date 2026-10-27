const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const [base,debug,monitor,exports,phase]=process.argv.slice(2),browser=await chromium.connectOverCDP('http://127.0.0.1:'+debug);
 try{
 let page;for(let i=0;i<100;i++){page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().startsWith(base));if(page)break;await new Promise(r=>setTimeout(r,100));}
 assert.ok(page,'Only attach to the isolated application URL');const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const session=await page.context().newCDPSession(page);await session.send('Emulation.setFocusEmulationEnabled',{enabled:false});
 await page.waitForFunction(()=>_state&&document.documentElement.dataset.desktop==='true');
 if(phase==='restore'){await page.waitForFunction(()=>document.documentElement.dataset.design==='orbit'&&document.documentElement.lang==='fa'&&document.documentElement.dataset.theme==='dark');assert.equal(await page.locator('#designSelect').inputValue(),'orbit');await page.evaluate(()=>desktopCommand('quit'));console.log('PASS real native restart on a new management port restores saved design, Persian and dark theme');return;}
 await page.waitForFunction(()=>document.getElementById('desktopPreferences').hidden===false);
 assert.equal(await page.evaluate(()=>window.__BALE_DESKTOP__),true);
 let windows=await(await fetch(monitor+'/window')).json();assert.ok(windows.some(w=>w.title==='BaleVPN'&&w.clientInset<24&&!w.visible),JSON.stringify(windows));assert.ok(!windows.some(w=>w.class==='ConsoleWindowClass'));
 assert.ok(await page.locator('#trayUnavailable').isHidden(),'A real tray icon must be available');
 await fetch(base+'/desktop/show',{method:'POST',headers:{Origin:base}});await page.waitForFunction(()=>!_desktopHidden);
 await page.evaluate(()=>{setWorkspaceTab('appearance');document.getElementById('languageSelect').value='fa';document.getElementById('themeSelect').value='dark';document.getElementById('designSelect').value='orbit';applyAppearance();});
 await page.waitForFunction(()=>!_appearanceSaving&&!_appearancePending&&_appearanceLastSaved===JSON.stringify(currentAppearance()));
 const stored=await (await fetch(base+'/appearance')).json();assert.equal(stored.appearance.layout,'orbit');assert.equal(stored.appearance.language,'fa');assert.equal(stored.appearance.theme,'dark');
 await page.waitForFunction(()=>document.getElementById('nativeTitlebar').getBoundingClientRect().height===48);
 assert.equal(await page.locator('html').getAttribute('dir'),'rtl');assert.ok(await page.locator('#nativeTitlebar').isVisible());
 assert.equal(await page.evaluate(()=>document.querySelector('.workspace-topbar').getBoundingClientRect().top<innerHeight*.65),true,'Native Orbit navigation must leave the actual page inside the viewport');
 const profilePort=await new Promise(resolve=>{const s=require('node:net').createServer();s.listen(0,'127.0.0.1',()=>{const port=s.address().port;s.close(()=>resolve(port));});});
 await page.evaluate(async port=>{const r=await fetch('/aggregate'),d=await r.json();d.config.paths[0].managementPort=port;await backupRequest('/aggregate',d.config);await loadAggregate();setWorkspaceTab('connection');document.getElementById('addClientAccount').click();},profilePort);
 await page.waitForFunction(()=>accountFrames.get(1)?.contentWindow.baleProfileUI?.ready()&&settingsDialogSlot===1);
 const profile=page.frame({url:base+'/aggregate/profiles/1/'});assert.ok(profile);await profile.waitForFunction(()=>_state.mode==='client');
 await profile.locator('#phoneInput').fill('+10000000001');await page.locator('#profileModalClose').click();await page.locator('[data-account="1"]').click();assert.equal(await profile.locator('#phoneInput').inputValue(),'+10000000001','Switching native accounts must retain the same frame and unsent form');
 await page.locator('#profileModal .settings-modal-nav [data-key=security]').click();assert.ok(await profile.locator('#serverCode').isVisible());await page.locator('#profileModal .settings-modal-nav [data-key=connection]').click();await page.locator('#profileModalClose').click();
 await page.evaluate(async()=>{await aggregateAction('/aggregate/worker',{slot:1,start:false});removeAccountFrame(1);});
 await page.evaluate(()=>{const field=document.getElementById('alwaysOnTop');field.checked=true;field.dispatchEvent(new Event('change'));});
 await page.waitForFunction(()=>document.getElementById('alwaysOnTop').checked);
 await page.evaluate(()=>{const field=document.getElementById('alwaysOnTop');field.checked=false;field.dispatchEvent(new Event('change'));});
 await page.evaluate(()=>desktopCommand('close'));await page.waitForFunction(()=>_desktopHidden,null,{polling:100});const hidden=await(await fetch(monitor+'/window')).json();assert.ok(hidden.some(w=>w.title==='BaleVPN'&&!w.visible));
 await fetch(base+'/desktop/show',{method:'POST',headers:{Origin:base}});await page.waitForFunction(()=>!_desktopHidden);
 await page.evaluate(()=>setWorkspaceTab('backup'));await page.waitForFunction(()=>document.querySelector('#backupAccounts input[value="0"]'));
 await page.evaluate(()=>{document.querySelector('#backupAccounts input[value="0"]').checked=true;document.getElementById('backupPassword').value='native-fixture-passphrase-123';document.getElementById('backupPasswordConfirm').value='native-fixture-passphrase-123';document.getElementById('backupExport').click();});
 await page.waitForFunction(()=>document.getElementById('backupExportStatus').textContent.includes('ذخیره شد'),null,{timeout:45000});
 assert.equal(await page.locator('#backupPassword').inputValue(),'');assert.equal(await page.locator('#backupPasswordConfirm').inputValue(),'');assert.equal(fs.readdirSync(exports).filter(n=>n.endsWith('.balevault')).length,1);
 const storage=await page.evaluate(()=>JSON.stringify(localStorage));assert.ok(!storage.includes('native-fixture-passphrase'));assert.ok(!storage.includes('+10000000001'));
 if(process.env.BALEVPN_SCREENSHOTS){fs.mkdirSync(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'native-backup-fa-dark.png')});}
 assert.deepEqual(errors,[]);await page.evaluate(()=>desktopCommand('quit'));console.log('PASS real WebView2/tray IPC, no caption/console, Persian native titlebar, hidden startup, close/show, preferences, native encrypted download, no password storage and quit');
 }finally{await browser.close().catch(()=>{});}
})().catch(e=>{console.error(e);process.exitCode=1;});
