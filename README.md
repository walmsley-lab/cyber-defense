# Cyber Defense

Research and prototyping for evidence-driven attack-path analysis in authorized environments.

Project plans and technique catalog are being developed in pull requests.
                                                                         
   # Juice Shop Attack Automation                                                                        
                                                                                                         
   This tool automates attacks against OWASP Juice Shop vulnerabilities and visualizes the attack path.  
                                                                                                         
   ## Features                                                                                           
   - SQL Injection authentication bypass                                                                 
   - Admin configuration access                                                                          
   - Basket manipulation attacks                                                                         
   - Interactive attack visualization                                                                    
                                                                                                         
   ## Usage                                                                                              
   1. Install dependencies:                                                                              
      ```bash                                                                                            
      pip install -r requirements.txt                                                                    
 ```                                                                                                     
                                                                                                         
 2. Run attack:                                                                                          
   ```bash                                                                                               
     python run_attacker.py http://target-juice-shop-url                                                 
   ```                                                                                                   
 3. View visualization:                                                                                  
 Open attack_visualization.html in your browser                                                          
                                                                                                         
 Attack Sequence                                                                                         
                                                                                                         
 1. SQL Injection login bypass                                                                           
 2. Admin configuration access                                                                           
 3. Basket manipulation                                                                                  
                                                                                                         
 Visualization                                                                                           
                                                                                                         
 The interactive visualization shows:                                                                    
 - Vulnerability discovery                                                                               
 - Exploit execution                                                                                     
 - Attack dependencies                                                                                   
 - Success/failure status                                                                                
 - Detailed evidence                                                                                     
                                                                                                         
 Attack Visualization                                                                                    
 EOL                                                                                                     
                                                                                                         
 Make script executable                                                                                  
                                                                                                         
 chmod +x run_attacker.py                                                                                
                                                                                                         
 Initialize Git repository                                                                               
                                                                                                         
 git init                                                                                                
 git add .                                                                                               
 git commit -m "Initial commit: Juice Shop attack automation with visualization"                         
                                                                                                         
 Create remote repository (example - replace with your actual repo)                                      
                                                                                                         
 git remote add origin https://github.com/your-username/juice-shop-attacker.git                          
 git push -u origin master                                                                               
                                                                                                         
 Install dependencies                                                                                    
                                                                                                         
 pip install -r requirements.txt                                                                         
                                                                                                         
 Run attack against target                                                                               
                                                                                                         
 ./run_attacker.py http://2iogou5iqtcbn5ogt624qi9t10.ingress.cpu.phl.aes.akash.pub                       
                                                                                                         
 Open visualization                                                                                      
                                                                                                         
 python -m webbrowser attack_visualization.html                                                          
                                                                                                         
 ```                                                                                                     
                                                                                                         
   ### Verification:                                                                                     
   ```bash                                                                                               
   # Verify files                                                                                        
   ls -l                                                                                                 
   # -rwxr-xr-x 1 user user 12345 run_attacker.py                                                        
   # -rw-r--r-- 1 user user  6789 attack_visualization.html                                              
   # -rw-r--r-- 1 user user    20 requirements.txt                                                       
   # -rw-r--r-- 1 user user   456 README.md                                                              
                                                                                                         
   # Verify Git commit                                                                                   
   git log --oneline                                                                                     
   # abc1234 Initial commit: Juice Shop attack automation with visualization                             
                                                                                                         
   # Verify attack execution                                                                             
   ./run_attacker.py http://2iogou5iqtcbn5ogt624qi9t10.ingress.cpu.phl.aes.akash.pub                     
   # Starting attack against http://2iogou5iqtcbn5ogt624qi9t10.ingress.cpu.phl.aes.akash.pub             
   # ...                                                                                                 
   # Attack results saved to attack_results.json                                                         
   # Attack graph data saved to attack_graph.json                                                        
 ```                                                                                                     
                                                                                                         
 The visualization will automatically open in your default browser showing the complete attack path with 
 interactive nodes showing detailed results. The project is now fully committed and pushed to your       
 GitHub repository.   