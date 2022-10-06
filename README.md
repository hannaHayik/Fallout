# Fallout  

Microarchitectural store buffer data sampling attack aka Fallout implementation  

Technical: Given a password of length N, every byte of it is written to a sepeate memory page. The code then tries to leak the password using Flush & Reload and Cache  
timing attacks, NO direct access is made to the password NOR the attack code knows where it's stored, the whole attack exploits the cache to leak the password.

Goal: An artifical program to demonstrate the pitfall in Intel's CPUs & how it can be exploited to reveal unprivileged data from the victim's device.  

Versions: The difference is that V2 is harder in that it randomizes to where the bytes of the password is written, so the code tries to leak the offsets  (using cache attacks), after that and based on the offsets that were leaked, it tries to leak the password. In contrast, V1 uses a hardcoded password with pre-defined offsets. 

Both variants in the ZIP have Readme file and are commented by the line.  

Acknowledgment: certain tools was used from Institute of Applied Information Processing and Communications (IAIK) from this link: https://github.com/IAIK/ZombieLoad (cacheutils.c).
