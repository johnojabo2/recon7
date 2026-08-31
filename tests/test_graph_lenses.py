import pytest
from storage.db import get_db_session, get_investigation_graph, Entity, ScanJob

def test_graph_lenses_synthesis():
    with get_db_session() as db:
        job = db.query(ScanJob).first()
        if not job:
            pytest.skip("No scan job in DB")
        
        # Test executive lens
        g_exec = get_investigation_graph(db, job.tenant_id, job.id, lens="executive")
        assert "nodes" in g_exec
        assert "edges" in g_exec
        assert g_exec["lens"] == "executive"
        
        # Test attack_surface lens
        g_atk = get_investigation_graph(db, job.tenant_id, job.id, lens="attack_surface")
        assert "nodes" in g_atk
        assert "edges" in g_atk
        assert g_atk["lens"] == "attack_surface"
        
        # Test composite lens
        g_comp = get_investigation_graph(db, job.tenant_id, job.id, lens="composite")
        assert "nodes" in g_comp
        assert "edges" in g_comp
        assert g_comp["lens"] == "composite"
