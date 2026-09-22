const {test}=require('node:test');
const assert=require('node:assert/strict');
const Database=require('better-sqlite3');
const {cancelStaleSponsored}=require('../lib/sponsored-history');

test('stale sponsored requests leave the queue but keep history and respect event/router scope',()=>{
  const db=new Database(':memory:');
  try {
    db.exec('CREATE TABLE admin_commands(id INTEGER PRIMARY KEY,event_id INTEGER,router_id INTEGER,command_type TEXT,status TEXT,created_at TEXT,applied_at TEXT)');
    const now=Date.parse('2026-09-22T18:00:00Z'),old=new Date(now-7200000).toISOString(),recent=new Date(now-60000).toISOString();
    const insert=db.prepare('INSERT INTO admin_commands VALUES(?,?,?,?,?,?,?)');
    insert.run(1,1,1,'SPONSORED','pending',old,null);
    insert.run(2,1,1,'SPONSORED','pending',recent,null);
    insert.run(3,1,1,'SPONSORED','applied',old,old);
    insert.run(4,1,1,'MANUAL_ADMIN','pending',old,null);
    insert.run(5,2,1,'SPONSORED','pending',old,null);
    insert.run(6,1,2,'SPONSORED','pending',old,null);
    assert.equal(cancelStaleSponsored(db,1,1,now),1);
    assert.deepEqual(db.prepare('SELECT status FROM admin_commands ORDER BY id').all().map(r=>r.status),['cancelled','pending','applied','pending','pending','pending']);
    assert.equal(cancelStaleSponsored(db,1,null,now),1);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM admin_commands').get().n,6);
    assert.equal(cancelStaleSponsored(db,1,null,now),0);
  } finally {db.close();}
});
