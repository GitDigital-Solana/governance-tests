### **governance-tests/test_policy_validator.py**
```python
#!/usr/bin/env python3
"""
Unit tests for Policy Validator
"""

import pytest
import json
import yaml
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent / 'governance-policy-schemas'))

from validator import PolicyValidator, ValidationIssue, Severity


class TestPolicyValidator:
    def setup_method(self):
        self.validator = PolicyValidator()
    
    def test_valid_policy(self):
        """Test valid policy passes validation."""
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "test-policy",
                "version": "1.0.0",
                "description": "Test policy"
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": [
                    {
                        "name": "test-rule",
                        "condition": "$.encryption != null",
                        "message": "Must have encryption"
                    }
                ]
            }
        }
        
        is_valid, issues = self.validator.validate(policy, "v1.0.0")
        assert is_valid == True
        assert len(issues) == 0
    
    def test_invalid_policy_missing_fields(self):
        """Test policy with missing required fields."""
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy"
            # Missing metadata and spec
        }
        
        is_valid, issues = self.validator.validate(policy, "v1.0.0")
        assert is_valid == False
        assert any(issue.severity == Severity.ERROR for issue in issues)
    
    def test_duplicate_rule_names(self):
        """Test policy with duplicate rule names."""
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "test-policy",
                "version": "1.0.0"
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": [
                    {
                        "name": "same-name",
                        "condition": "$.encryption != null"
                    },
                    {
                        "name": "same-name",  # Duplicate
                        "condition": "$.versioning == true"
                    }
                ]
            }
        }
        
        is_valid, issues = self.validator.validate(policy, "v1.0.0")
        assert is_valid == False
        assert any("duplicate" in issue.message.lower() for issue in issues)
    
    def test_invalid_jsonpath(self):
        """Test policy with invalid JSONPath expression."""
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "test-policy",
                "version": "1.0.0"
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": [
                    {
                        "name": "test-rule",
                        "condition": "invalid jsonpath!!!",  # Invalid
                        "message": "Test message"
                    }
                ]
            }
        }
        
        is_valid, issues = self.validator.validate(policy, "v1.0.0")
        assert is_valid == False
        assert any("jsonpath" in issue.message.lower() for issue in issues)
    
    def test_best_practice_warnings(self):
        """Test that best practice violations generate warnings."""
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "test-policy",
                "version": "1.0.0"
                # Missing description
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": [
                    {
                        "name": "test-rule",
                        "condition": "$.encryption != null"
                        # Missing severity
                    }
                ]
            }
        }
        
        is_valid, issues = self.validator.validate(policy, "v1.0.0")
        assert is_valid == True  # Still valid, just warnings
        assert any(issue.severity == Severity.INFO for issue in issues)
        assert any("description" in issue.message.lower() for issue in issues)
        assert any("severity" in issue.message.lower() for issue in issues)
    
    def test_severity_validation(self):
        """Test severity field validation."""
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "test-policy",
                "version": "1.0.0",
                "severity": "unknown-severity"  # Invalid
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": [
                    {
                        "name": "test-rule",
                        "condition": "$.encryption != null",
                        "severity": "invalid-severity"  # Invalid
                    }
                ]
            }
        }
        
        is_valid, issues = self.validator.validate(policy, "v1.0.0")
        # Should have warnings about unusual severity values
        assert any("unusual severity" in issue.message.lower() for issue in issues)
    
    def test_file_validation(self):
        """Test validation from file."""
        # Create temporary policy file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "apiVersion": "governance/v1.0.0",
                "kind": "Policy",
                "metadata": {
                    "name": "file-test",
                    "version": "1.0.0"
                },
                "spec": {
                    "target": {
                        "resourceType": "aws_s3_bucket"
                    },
                    "rules": [
                        {
                            "name": "test-rule",
                            "condition": "$.encryption != null"
                        }
                    ]
                }
            }, f)
            temp_path = f.name
        
        try:
            result = self.validator.validate_file(temp_path, "v1.0.0")
            assert result["valid"] == True
            assert result["policy_name"] == "file-test"
        finally:
            Path(temp_path).unlink()


class TestSchemaMigrator:
    def test_migration_v1_0_to_v1_1(self):
        """Test migration from v1.0.0 to v1.1.0."""
        from validator import SchemaMigrator
        
        migrator = SchemaMigrator()
        
        policy_v1_0 = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "test",
                "version": "1.0.0",
                "labels": {
                    "env": "prod"
                }
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": []
            }
        }
        
        migrated = migrator.migrate(policy_v1_0, "v1.0.0", "v1.1.0")
        
        # Check fields were migrated
        assert "tags" in migrated["metadata"]
        assert migrated["metadata"]["tags"]["env"] == "prod"
        assert "labels" not in migrated["metadata"]
        assert migrated["spec"].get("enforcement") == "enforce"
    
    def test_migration_invalid_version(self):
        """Test migration with invalid version."""
        from validator import SchemaMigrator
        
        migrator = SchemaMigrator()
        
        with pytest.raises(ValueError, match="No migration path"):
            migrator.migrate({}, "v1.0.0", "v2.0.0")


@pytest.mark.integration
class TestIntegration:
    """Integration tests."""
    
    def test_end_to_end_validation(self, tmp_path):
        """Test end-to-end validation workflow."""
        # Create policy directory
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        
        # Write a valid policy
        policy_file = policy_dir / "test-policy.yaml"
        with open(policy_file, 'w') as f:
            yaml.dump({
                "apiVersion": "governance/v1.0.0",
                "kind": "Policy",
                "metadata": {
                    "name": "integration-test",
                    "version": "1.0.0",
                    "description": "Integration test policy"
                },
                "spec": {
                    "target": {
                        "resourceType": "aws_s3_bucket"
                    },
                    "rules": [
                        {
                            "name": "encryption-required",
                            "condition": "$.encryption != null",
                            "message": "Must have encryption",
                            "severity": "high"
                        }
                    ]
                }
            }, f)
        
        # Validate the policy
        validator = PolicyValidator()
        result = validator.validate_file(str(policy_file))
        
        assert result["valid"] == True
        assert len(result["issues"]) == 0


@pytest.mark.performance
class TestPerformance:
    """Performance tests."""
    
    def test_validation_performance(self):
        """Test validation performance with large policies."""
        import time
        
        # Create a large policy with many rules
        policy = {
            "apiVersion": "governance/v1.0.0",
            "kind": "Policy",
            "metadata": {
                "name": "performance-test",
                "version": "1.0.0"
            },
            "spec": {
                "target": {
                    "resourceType": "aws_s3_bucket"
                },
                "rules": []
            }
        }
        
        # Add 1000 rules
        for i in range(1000):
            policy["spec"]["rules"].append({
                "name": f"rule-{i}",
                "condition": f"$.property_{i} != null",
                "message": f"Rule {i} violation"
            })
        
        validator = PolicyValidator()
        
        start_time = time.time()
        is_valid, issues = validator.validate(policy, "v1.0.0")
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        assert is_valid == True
        # Should complete in under 2 seconds
        assert execution_time < 2.0
        
        print(f"Validation of 1000 rules completed in {execution_time:.2f} seconds")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
