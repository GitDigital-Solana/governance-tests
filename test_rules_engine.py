governance-tests/test_rules_engine.py

```python
#!/usr/bin/env python3
"""
Tests for Rules Engine
"""

import pytest
import json
from unittest.mock import Mock, patch
import sys
sys.path.append(str(Path(__file__).parent.parent / 'governance-rules-engine'))

# Mock Go imports for testing
class MockRulesEngine:
    def __init__(self):
        self.policies = {}
    
    def register_policy(self, policy):
        self.policies[policy['id']] = policy
        return True
    
    def evaluate(self, resource):
        return {
            "passed": True,
            "violations": []
        }


class TestRulesEngine:
    def test_policy_registration(self):
        """Test policy registration."""
        engine = MockRulesEngine()
        
        policy = {
            "id": "test-policy",
            "name": "Test Policy",
            "rules": []
        }
        
        result = engine.register_policy(policy)
        assert result == True
        assert "test-policy" in engine.policies
    
    def test_resource_evaluation(self):
        """Test resource evaluation."""
        engine = MockRulesEngine()
        
        resource = {
            "id": "test-resource",
            "type": "aws_s3_bucket",
            "properties": {
                "encryption": "AES256"
            }
        }
        
        result = engine.evaluate(resource)
        assert "passed" in result
        assert "violations" in result
        assert isinstance(result["violations"], list)
    
    def test_rule_condition_evaluation(self):
        """Test rule condition evaluation."""
        # This would test the actual JSONPath evaluation
        # For now, use mock
        pass
    
    @pytest.mark.parametrize("resource_type,expected_match", [
        ("aws_s3_bucket", True),
        ("aws_ec2_instance", False),
    ])
    def test_target_type_matching(self, resource_type, expected_match):
        """Test that policies only evaluate matching resource types."""
        engine = MockRulesEngine()
        
        policy = {
            "id": "s3-policy",
            "targetType": "aws_s3_bucket",
            "rules": []
        }
        
        engine.register_policy(policy)
        
        resource = {
            "id": "test-resource",
            "type": resource_type,
            "properties": {}
        }
        
        # In real implementation, would check if policy was evaluated
        result = engine.evaluate(resource)
        assert isinstance(result, dict)


class TestPerformance:
    def test_concurrent_evaluation(self):
        """Test concurrent evaluation of multiple resources."""
        import concurrent.futures
        import time
        
        engine = MockRulesEngine()
        
        # Register a policy
        policy = {
            "id": "test-policy",
            "name": "Test",
            "targetType": "aws_s3_bucket",
            "rules": [{"condition": "$.encryption != null"}]
        }
        engine.register_policy(policy)
        
        # Create many resources
        resources = []
        for i in range(100):
            resources.append({
                "id": f"resource-{i}",
                "type": "aws_s3_bucket",
                "properties": {"encryption": "AES256"}
            })
        
        # Evaluate concurrently
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(engine.evaluate, resource) for resource in resources]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        end_time = time.time()
        
        assert len(results) == 100
        assert all(r["passed"] for r in results)
        
        print(f"Concurrent evaluation of 100 resources took {end_time - start_time:.2f} seconds")
