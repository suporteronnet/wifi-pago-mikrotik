function cancelStaleSponsored(db, eventId, routerId=null, now=Date.now()) {
  const cutoff=new Date(now-60*60*1000).toISOString();
  return db.prepare(`UPDATE admin_commands SET status='cancelled'
    WHERE event_id=? AND command_type='SPONSORED' AND status='pending'
      AND applied_at IS NULL AND julianday(created_at)<julianday(?)
      AND (? IS NULL OR router_id=?)`).run(eventId,cutoff,routerId,routerId).changes;
}
module.exports={cancelStaleSponsored};
