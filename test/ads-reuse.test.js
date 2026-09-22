const {test}=require('node:test');
const assert=require('node:assert/strict');
const Database=require('better-sqlite3');
const fs=require('node:fs');
test('blocked grants cannot be reused; new grants and other routers remain independent',()=>{
  const source=fs.readFileSync(require.resolve('../server.js'),'utf8');
  const sql=source.match(/const existing=db\.prepare\(`(SELECT c\.command_ref[\s\S]*?)`\)/)[1];
  const db=new Database(':memory:');
  try{
    db.exec(`CREATE TABLE admin_commands(id INTEGER PRIMARY KEY,command_ref TEXT,event_id INTEGER,router_id INTEGER,mac TEXT,command_type TEXT,status TEXT,applied_at TEXT,minutes INTEGER);
      INSERT INTO admin_commands VALUES(1,'old',1,1,'AA','SPONSORED','applied',datetime('now'),15);`);
    const query=db.prepare(sql);
    assert.equal(query.get(1,1,'AA').command_ref,'old');
    db.exec("INSERT INTO admin_commands VALUES(2,'block',1,1,'AA','BLOCK_NOW','pending',NULL,NULL)");
    assert.equal(query.get(1,1,'AA'),undefined);
    db.exec("INSERT INTO admin_commands VALUES(3,'new',1,1,'AA','SPONSORED','pending',NULL,15)");
    assert.equal(query.get(1,1,'AA').command_ref,'new');
    db.exec("INSERT INTO admin_commands VALUES(4,'other',1,2,'AA','UNBYPASS','applied',NULL,NULL)");
    assert.equal(query.get(1,1,'AA').command_ref,'new');
  }finally{db.close();}
});
