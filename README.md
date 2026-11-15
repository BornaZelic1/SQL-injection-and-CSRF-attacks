Git Repo: https://github.com/BornaZelic1/SQL-injection-and-CSRF-attacks

Webapp: https://web2-lab2-3dey.onrender.com/

Implementirane ranjivosti: SQL injection i Cross Site Request Forgery

Uspješno je implementirano SQL injection u koji se može poslati tautologija, UNION za dodavanje novih select upita. Zbog Cloudflaira koji je iznad svake besplatne Render inačice, nije moguće tautologiju isprobati na inačici koja je podignuta na cloud. Zbog toga, u nastavku će biti navedene upute za lokalno testiranje.
Uspješno je implementirano CSRF. Kako bi se testiralo, potrebno je prijaviti se s korisničkim imenom ana i lozinkom ana123 ili ivan i lozinkom ivan123. Nakon toga dovoljno je kliknuti na link za zločudnu stranicu kako bi se vidjelo da se u polju traženi e-mail upisuje napadaćev mail.

Za testiranje SQL Injectiona potrebno je označiti Ranjivost uključena. Ako je ta postavka postavljena, sve što korisnik unese se nadovezuje ravno u SQL upit u nastavku WHERE dijela querya. Ako ranjivost nije uključena, upit se parametrizira. Za svaki unos, stranica prikazuje rezultat, pa je odmah vidljiv rezultat unosa. Implementirani su UNION i tautologija napadi kako je opisano na stranici i u prethodnim odlomcima. Ovakva je implementacija odabrana jer jasno prikazuje razliku između SQL injectiona i implementacije bez ranjivosti, a razlika u kodu je jedna linija. 
Za testiranje CSRF potrebno je označiti Ranjivost uključena. Potrebno je prijavljivanje kao jedan od navedenih usera te pokušaj promjene vlastitog maila. Ako se nakon toga pritisne na napadačev link, email koji je user postavio se zamijeni napadačevim. Ako se ranjivost isključi, CSRF napad se odbije, što se ispiše kraj ostalih logova. Ovakva je implementacija odabrana jer promjenom odabrane vrijednosti jasno pokazuje razliku između ranjivosti i sigurne verzije aplikacije.

Sve traženo u zadatku je implementirano. Jedini problem je u obliku Cloudflaira nad aplikacijom koju postavlja Render, zbog čega je tautologiju potrebno isprobati lokalno. U nastavku slijede upute za lokalno pokretanje projekta.

Nije moguće izvršiti napade unosa ili brisanja podataka, kreiranje ili brisanja tablica zato što je trentuno implementirano s db.prepare(sql).all() koji obavlja samo jednu sql komandu, što je logičan način za implementaciju u produkciji. S obzirom da navedene ne implementirane naredbe trebaju biti zaseban query, ne mogu se izvesti s navedenom linijom, nego bi se trebala koristiti funkcija koja pokreće sve predane sql naredbe te tek onda napraviti dodatni select koji bi vratio rezultate. Time bi rješenje postalo gimicky pa je to izostavljeno.

Aplikaciju je moguće pokrenuti kloniranjem u gore navedeni git repo i pokretanjem u konzoli naredbama "npm install && npm start". Kao što je navedeno u .nvmrc, za rad aplikacije potreban je Node.js 24. Aplikacija se otvara na portu 3000. Korisnička imena i zaporke su parovi (ana, ana123) i (ivan, ivan123)