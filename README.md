# DumpVAC
PoC to disable VAC and dump modules with automatic decryption.

# Some info (Possibly outdated, this screenshot was taken about a year ago)
![Picture](https://github.com/RenardDev/DumpVAC/blob/main/unknown.png)

* The first module always responds to session initialization.
* Modules can be different (for example, a scanner for illegal controllers that emulate a player but in reality are hardware cheats; a scanner for processes and its modules)
* All modules have their own purpose.
* Modules are received from Steam servers and the server does not care if it has not received a response with the results of module execution. (DumpVAC blocks the execution of modules and the response remains filled with zeros)
* Modules can be specially created for specific tasks. (There are general modules that always work and there are modules that are created to search for specific cheats)

# Short manual
1. Run `Console.exe`.
2. Run any game with VAC.
3. Done.
4. (To restore VAC - Press CTRL+C / To restart DumpVAC for reuse - Close and Open again)
