# HOLDMYNUGGETS-SENTINEL-SOC-ANALSYT HANDS ON LAB
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/c3ca8940-fb7f-4941-807a-5e74f65d73f6" />

# GENERATING AN ATTACK 

## Objective
This lab exercise teaches how to detect credential theft attempts using LimaCharlie EDR (Endpoint Detection and Response). The learning objective is to understand how attackers use techniques like LSASS memory dumping to steal credentials, and then learn to craft detection rules to identify such malicious activities. Students will gain hands-on experience by first performing the attack using a Sliver C2 session, then analyzing the telemetry in LimaCharlie, and finally creating and testing a detection rule that successfully alerts on this behavior.


### Skills Learned
- Generating attacks .
- Detecting.
- Monitoring logs.
- Threat hunting.
- Blocking attacks.


### Tools Used
- Launching Sliver client
- SIEM EDR TELEMETRY (Lima charlie)
- credential stealing with lsass.exe

## Steps
- launching sliver client, an open-source, cross-platform adversary emulation and red team framework
- <img width="975" height="594" alt="image" src="https://github.com/user-attachments/assets/d9a7a8e7-fbef-4101-8215-9b8a3ddfe46e" />
- Next,verifying if sliver is listening for c2 callbacks on http listener, starting a job based on jobs results thus "No active jobs". a job has been started and this means sliver is listening for c2 callback on http
- <img width="715" height="341" alt="image" src="https://github.com/user-attachments/assets/02e04130-9dfe-4ccd-9f93-c80e364c60d5" />
- Generating C2 Implant, In the Sliver client terminal launched above, generates C2 implant and drop it into a directory we'll later be able to access from the Windows VM. c2 implant will generate an executable malware that is saved in the directory /var/www/payloads + the name of the malware file generated.
- <img width="975" height="256" alt="image" src="https://github.com/user-attachments/assets/33e4b2e8-d743-43b6-80ab-77431e4b3127" />
- Next , call our implants to view your malware files
- <img width="975" height="151" alt="image" src="https://github.com/user-attachments/assets/054626c4-5acb-427e-bec3-3e6393e634b4" />
-launching the genrate malware file (READY_SODA.exe) on target machine , in this case we assume the target downloads the executable file. Onces the target opens the file, C2 implant will callback to sliver server by starting a session
- <img width="975" height="292" alt="image" src="https://github.com/user-attachments/assets/c833e9cf-bea5-4b24-9b1b-fa479aab70a0" />
- <img width="975" height="62" alt="image" src="https://github.com/user-attachments/assets/8c2ffe0d-ecfa-4bfc-8649-ea613895ee9e" />
- Now to interact with the new C2 session,call sessions and use the session ID of the Alive malware file.
- <img width="975" height="225" alt="image" src="https://github.com/user-attachments/assets/26236fd0-ecf9-42fe-a1e6-4a95a882620e" />
- On the Ready_soda session we can explore for network connections with Netstat,gives us proof of the connection.
- <img width="975" height="635" alt="image" src="https://github.com/user-attachments/assets/b17604a4-5ec4-4b10-b27c-008c2fed3a55" />
- <img width="975" height="585" alt="image" src="https://github.com/user-attachments/assets/32f06531-6e67-42c6-a0b2-e8b1d1a4aa92" />
- Furmore, identify running processes on the remote system, if there any defence tools will be heighted in red
- <img width="816" height="991" alt="image" src="https://github.com/user-attachments/assets/5438b07a-765c-4c5b-93e5-965693fcaf1c" />
- Back to our organization, the dashboard is already showcasing data, but the focus is on our window sensor focused on processes
- <img width="975" height="647" alt="image" src="https://github.com/user-attachments/assets/069e38d9-93e1-4622-9105-ae8e198227fe" />
- <img width="975" height="351" alt="image" src="https://github.com/user-attachments/assets/ffb08bf6-6700-4157-82fa-e8d5857247ab" />
- One of the easiest ways to spot unusual processes is to simply look for ones that are NOT signed. The circular green check mark indicates the process binary is signed/trusted.We notice some processes are active and running on the network including READY_SODA.exe
- <img width="975" height="714" alt="image" src="https://github.com/user-attachments/assets/65473e70-5738-4068-b1b3-89ec2e63f348" />
- <img width="975" height="695" alt="image" src="https://github.com/user-attachments/assets/ce3f48ca-6d99-4a69-8bd9-5f84a22fe80f" />
- Under Networks c2 implant is established
- <img width="975" height="412" alt="image" src="https://github.com/user-attachments/assets/05f66284-880c-4b5f-b54b-d703d8450a52" />
- Under File system, locate the path from which the file is running
- <img width="975" height="331" alt="image" src="https://github.com/user-attachments/assets/15987674-e0fa-47c5-ac5a-7c4aeb40a5b6" />
- If the file is a common/well-known malware sample, you will know it right away when VirusTotal reports it as such. However, “Item not found” on VT does not mean that this file is innocent, just that it’s never been seen before by VirusTotal. This makes sense because we just generated this payload ourselves, so of course it’s not likely to be seen by VirusTotal before. This is an important lesson for any analyst to learn — if you already suspect a file to be possible malware, but VirusTotal has never seen it before, trust your gut. This actually makes a file even more suspicious because nearly everything has been seen by VirusTotal
- Click “Timeline” on the left-side menu of our sensor. This is a near real-time view of EDR telemetry + event logs streaming from this system.
- <img width="975" height="713" alt="image" src="https://github.com/user-attachments/assets/20129c7d-e3fb-4926-9275-b2e412ebbb42" />
- <img width="975" height="728" alt="image" src="https://github.com/user-attachments/assets/6988d3a7-59cc-4788-aeb7-8065735a74c7" />
- stealing credentials on a system. We’re going to dump the lsass.exe process from memory, a critical Windows process which holds sensitive information, such as credentials.
- <img width="975" height="219" alt="image" src="https://github.com/user-attachments/assets/b94b9fe1-412e-44cc-9e17-dceb71c7d23e" />
- <img width="975" height="101" alt="image" src="https://github.com/user-attachments/assets/541cb409-2f34-41bd-b53d-58bef15e8510" />
- next locate the creds on target machine, for now I wont go into the details of extract the credentials , this process was strategicaly to showcase adversaries.
- <img width="975" height="439" alt="image" src="https://github.com/user-attachments/assets/4fc69099-1c7e-483c-afd8-a4354773381c" />
- Under our Telemtry, we can detect credential theft and investigate further
- <img width="975" height="483" alt="image" src="https://github.com/user-attachments/assets/8f10acd9-d78a-444f-b9cf-a93938967676" />
- <img width="975" height="373" alt="image" src="https://github.com/user-attachments/assets/6f26440c-d969-4e3a-939a-0e516f4d9111" />


# DETECTING ATTACK
- By the end of this lab,  will be able to detect adversarial activity in LimaCharlie by analyzing telemetry from a Windows VM sensor. learn how to filter and investigate SENSITIVE_PROCESS_ACCESS events, specifically identifying credential dumping attempts targeting lsass.exe. Additionally, they will gain hands-on experience in crafting a Detection & Response (D&R) rule to automatically alert on such activity. Finally, they will validate their detection logic by executing the attack again and confirming that their custom detection rule successfully identifies the threat in real-time.
- <img width="975" height="412" alt="image" src="https://github.com/user-attachments/assets/634362c3-7e27-407b-b08b-92e6de32067f" />
- <img width="975" height="830" alt="image" src="https://github.com/user-attachments/assets/13678018-66e2-41af-bc79-8250c732baaa" />
- lets build a detection rule that will alert anytime this kinda of activity occurs.
- <img width="718" height="588" alt="image" src="https://github.com/user-attachments/assets/0da52220-c389-4a38-8fec-638400b36161" />
- <img width="975" height="452" alt="image" src="https://github.com/user-attachments/assets/485fc842-d36f-49a8-b70f-f674fdf227e2" />
- We’re specifying that this detection should only look atSENSITIVE_PROCESS_ACCESS events where the victim, or target process ends with lsass.exe - excluding a very noisy false positive in this VM, wmiprvse.exe
- <img width="975" height="290" alt="image" src="https://github.com/user-attachments/assets/d7a75ce4-ed66-463c-8894-0f94ef373fd3" />
- We’re telling LimaCharlie to simply generate a detection “report” anytime this detection occurs.  check out the docs. We could ultimately tell this rule to do all sorts of things, like terminate the offending process chain, etc. Let’s keep it simple for now.
- <img width="975" height="1123" alt="image" src="https://github.com/user-attachments/assets/6be8e50e-5618-4422-8c35-bb32af8afd51" />
- <img width="975" height="500" alt="image" src="https://github.com/user-attachments/assets/a0b8e87a-14ae-4cfc-bcf5-77adbcced60c" />





















































