import requests
import sys
import json
from datetime import datetime, timedelta

class SenateAPITester:
    def __init__(self, base_url="https://sa-senate-gov.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tokens = {}
        self.users = {}
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
        
        result = {
            "test": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {name}")
        if details:
            print(f"    Details: {details}")

    def run_test(self, name, method, endpoint, expected_status, data=None, token=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)

            success = response.status_code == expected_status
            details = f"Status: {response.status_code}"
            
            if not success:
                details += f" (expected {expected_status})"
                try:
                    error_data = response.json()
                    details += f", Response: {error_data}"
                except:
                    details += f", Response: {response.text[:200]}"
            
            self.log_test(name, success, details)
            
            if success:
                try:
                    return response.json()
                except:
                    return {}
            return None

        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return None

    def test_auth_flow(self):
        """Test authentication flow"""
        print("\n🔐 Testing Authentication...")
        
        # Test user registration
        test_user_data = {
            "email": f"test_user_{datetime.now().strftime('%H%M%S')}@senate.gov",
            "password": "testpass123",
            "full_name": "Test User"
        }
        
        response = self.run_test(
            "User Registration",
            "POST",
            "auth/register",
            200,
            data=test_user_data
        )
        
        if response and 'token' in response:
            self.tokens['test_user'] = response['token']
            self.users['test_user'] = response['user']
        
        # Test login with provided credentials
        test_credentials = [
            ("techadmin@senate.gov", "admin123", "tech_admin"),
            ("speaker@senate.gov", "speaker123", "speaker"),
            ("senator1@senate.gov", "password123", "senator")
        ]
        
        for email, password, role_key in test_credentials:
            response = self.run_test(
                f"Login - {role_key}",
                "POST",
                "auth/login",
                200,
                data={"email": email, "password": password}
            )
            
            if response and 'token' in response:
                self.tokens[role_key] = response['token']
                self.users[role_key] = response['user']
        
        # Test /auth/me endpoint
        if 'tech_admin' in self.tokens:
            self.run_test(
                "Get Current User",
                "GET",
                "auth/me",
                200,
                token=self.tokens['tech_admin']
            )

    def test_bills_api(self):
        """Test bills functionality"""
        print("\n📋 Testing Bills API...")
        
        # Get bills
        self.run_test("Get Bills", "GET", "bills", 200)
        
        # Create bill (as senator)
        if 'senator' in self.tokens:
            bill_data = {
                "title": "Test Bill - Environmental Protection",
                "description": "A test bill for environmental protection measures"
            }
            
            response = self.run_test(
                "Create Bill",
                "POST",
                "bills",
                200,
                data=bill_data,
                token=self.tokens['senator']
            )
            
            if response and 'id' in response:
                bill_id = response['id']
                
                # Test voting on bill
                self.run_test(
                    "Vote on Bill - FOR",
                    "POST",
                    f"bills/{bill_id}/vote",
                    200,
                    data={"vote": "FOR"},
                    token=self.tokens['senator']
                )
                
                # Test changing vote
                self.run_test(
                    "Vote on Bill - AGAINST",
                    "POST",
                    f"bills/{bill_id}/vote",
                    200,
                    data={"vote": "AGAINST"},
                    token=self.tokens['senator']
                )
                
                # Test opening voting (as speaker)
                if 'speaker' in self.tokens:
                    self.run_test(
                        "Open Bill Voting",
                        "PUT",
                        f"bills/{bill_id}/status?status=VOTING",
                        200,
                        token=self.tokens['speaker']
                    )
                    
                    # Test speaker decision
                    decision_data = {
                        "status": "APPROVED",
                        "decision": "Bill approved after thorough review"
                    }
                    
                    self.run_test(
                        "Speaker Decision",
                        "POST",
                        f"bills/{bill_id}/decision",
                        200,
                        data=decision_data,
                        token=self.tokens['speaker']
                    )

    def test_sessions_api(self):
        """Test sessions functionality"""
        print("\n📅 Testing Sessions API...")
        
        # Get sessions
        self.run_test("Get Sessions", "GET", "sessions", 200)
        
        # Create session (as speaker)
        if 'speaker' in self.tokens:
            session_data = {
                "title": "Weekly Senate Meeting",
                "description": "Regular weekly meeting to discuss pending bills",
                "date": (datetime.now() + timedelta(days=7)).isoformat()
            }
            
            response = self.run_test(
                "Create Session",
                "POST",
                "sessions",
                200,
                data=session_data,
                token=self.tokens['speaker']
            )
            
            if response and 'id' in response:
                session_id = response['id']
                
                # Test attendance marking
                attendance_data = [
                    {"user_id": "test-user-id", "user_name": "Test User", "present": True}
                ]
                
                self.run_test(
                    "Mark Attendance",
                    "POST",
                    f"sessions/{session_id}/attendance",
                    200,
                    data=attendance_data,
                    token=self.tokens['speaker']
                )

    def test_users_api(self):
        """Test users management"""
        print("\n👥 Testing Users API...")
        
        # Get users
        self.run_test("Get Users", "GET", "users", 200)
        
        # Test user update (as tech admin)
        if 'tech_admin' in self.tokens and 'test_user' in self.users:
            user_id = self.users['test_user']['id']
            update_data = {
                "roles": ["SENATOR"],
                "note": "Test senator from automated testing"
            }
            
            self.run_test(
                "Update User Roles",
                "PUT",
                f"users/{user_id}",
                200,
                data=update_data,
                token=self.tokens['tech_admin']
            )

    def test_news_api(self):
        """Test news functionality"""
        print("\n📰 Testing News API...")
        
        # Get news
        self.run_test("Get News", "GET", "news", 200)
        
        # Create news (as speaker)
        if 'speaker' in self.tokens:
            news_data = {
                "title": "Senate Automation Testing",
                "content": "This is a test news article created during automated testing"
            }
            
            response = self.run_test(
                "Create News",
                "POST",
                "news",
                200,
                data=news_data,
                token=self.tokens['speaker']
            )

    def test_decrees_api(self):
        """Test decrees functionality"""
        print("\n📜 Testing Decrees API...")
        
        # Get decrees
        self.run_test("Get Decrees", "GET", "decrees", 200)
        
        # Create decree (as speaker)
        if 'speaker' in self.tokens:
            decree_data = {
                "title": "Test Decree - Senate Procedures",
                "content": "This is a test decree regarding senate procedures"
            }
            
            response = self.run_test(
                "Create Decree",
                "POST",
                "decrees",
                200,
                data=decree_data,
                token=self.tokens['speaker']
            )

    def test_settings_api(self):
        """Test settings functionality"""
        print("\n⚙️ Testing Settings API...")
        
        # Get settings
        self.run_test("Get Settings", "GET", "settings", 200)
        
        # Update settings (as tech admin)
        if 'tech_admin' in self.tokens:
            settings_data = {
                "senate_name": "Test Senate of San Andreas",
                "welcome_text": "Welcome to the automated test environment",
                "primary_color": "#1e40af",
                "secondary_color": "#64748b"
            }
            
            self.run_test(
                "Update Settings",
                "PUT",
                "settings",
                200,
                data=settings_data,
                token=self.tokens['tech_admin']
            )

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting San Andreas Senate API Testing...")
        print(f"Testing against: {self.base_url}")
        
        self.test_auth_flow()
        self.test_bills_api()
        self.test_sessions_api()
        self.test_users_api()
        self.test_news_api()
        self.test_decrees_api()
        self.test_settings_api()
        
        # Print summary
        print(f"\n📊 Test Summary:")
        print(f"Tests run: {self.tests_run}")
        print(f"Tests passed: {self.tests_passed}")
        print(f"Success rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        # Return results for further processing
        return {
            "total_tests": self.tests_run,
            "passed_tests": self.tests_passed,
            "success_rate": self.tests_passed/self.tests_run*100 if self.tests_run > 0 else 0,
            "test_results": self.test_results
        }

def main():
    tester = SenateAPITester()
    results = tester.run_all_tests()
    
    # Save results to file
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    return 0 if results['success_rate'] > 80 else 1

if __name__ == "__main__":
    sys.exit(main())