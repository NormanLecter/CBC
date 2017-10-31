var aesjs = require('aes-js');
var fs = require('fs');

// TODO: dopełnienie bloków do 16 bajtów (w razie zbyt krótkiego bloku)
// TODO: zabezpiecznie/sprawdzenie długości bloków czy 16 bajtów (stworzony szyfrator i deszyfrator)
// TODO: testy na plikach 50KB i 100KB

// przykładowy 128 bitowego klucz
var key = [ 11, 67, 9, 4, 5, 98, 7, 8, 19, 10, 90, 12, 33, 14, 75, 16];

//wczytanie plikow - Sync by zablokowac program, by wczytywanie pliku nie wpływało na wyniki obliczeń czasowych
var plik10KB = fs.readFileSync('plik10KB.txt','Utf8');

var wynikowySzyfrogram = new Array();
var wynikowySzyfrogramCbc = new Array();
var odszyfrowanyTekst;
var zaszyfrowaneBajty;
var tekstOdszyfrowany;
var fragmentTekstu;
var fragmentTablicy;
var bajty;
var licznik = 0;

/******************************* AES  + ECB *****************************************************************/

function szyfrujAesEcb(wczytanyTekst){
  for(var i = 0; i < wczytanyTekst.length; i+=16){
      //pobranie do zmiennej 'text' pierwszych 16 znaków
      fragmentTekstu = wczytanyTekst.substr(i,(i+16));
      //zamiana każdej litery na DEC ASCII, np. a => 97
      bajty = aesjs.utils.utf8.toBytes(fragmentTekstu);
      //zaszyfrowanie tekstu -> AES + ECB
      zaszyfrowaneBajty = aesEcb.encrypt(bajty);
      //dodanie zaszyfrowanego bloku do pliku wynikowego
      wynikowySzyfrogram[licznik] = zaszyfrowaneBajty;
      licznik++;
  }
}

function deszyfrujAesEcb(tekstZaszyfrowany){
  for(var i = 0; i < tekstZaszyfrowany.length; i++){
      //odszyfrowanie fragmentu - tablica bajtów
      fragmentOdszyfrowany = aesEcb.decrypt(tekstZaszyfrowany[i]);
      //dodanie odszyfrowanego (już w znakach) fragmentu do zmiennej wynikowej
      odszyfrowanyTekst += aesjs.utils.utf8.fromBytes(fragmentOdszyfrowany);
  }
}

//wygenerowanie nowego obiektu do szyfrowania AES -> podanie klucza
var aesEcb = new aesjs.ModeOfOperation.ecb(key);

console.log('\n');
//rozpoczecie pomiaru czasu dla AES + ECB - szyfrowanie - plik 10KB
console.time('Czas-Szyfrowanie-AesEcb-plik-10KB');
szyfrujAesEcb(plik10KB);
console.timeEnd('Czas-Szyfrowanie-AesEcb-plik-10KB');
console.log('\n');
//rozpoczecie pomiaru czasu dla AES + ECB - deszyrowanie - plik 10KB
console.time('Czas-Deszyfrowanie-AesEcb-plik-10KB')
deszyfrujAesEcb(wynikowySzyfrogram);
console.timeEnd('Czas-Deszyfrowanie-AesEcb-plik-10KB')
console.log('\n');

/******************************* AES  + CBC **********************************/

// wektor inicjujacy IV
var iv = [ 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 ];
//instatnia ostatniego bloku zaszyfrowanego; zainiciowanie wektorem inicjujacym
var ostatniBlokSzyfrujacy = iv;
// AES do kodowanie blokow
var mojAes = new aesjs.ModeOfOperation.cbc(key,iv);

//zwraca zaszyfrowany AES + CBC jeden (!) blok
function mojeCbcSzyfrowanie(tekstAscii){
  var zaszyfrowanyTekst = new Uint8Array(tekstAscii.length);
  var  blok = new Uint8Array(16);
  //petla; dla kazdego bloku  tekstu wykona sie tylko raz
  for(var i = 0; i < tekstAscii.length; i += 16){
      //przekopiowanie  fragmentu tekstu w  ASCII do pojedynczego bloku
      blok = tekstAscii;
      for(var j = 0; j < 16; j++){
        blok[j] ^= ostatniBlokSzyfrujacy[j];
      }
      ostatniBlokSzyfrujacy = mojAes.encrypt(blok);
      zaszyfrowanyTekst = ostatniBlokSzyfrujacy;
  }
  return zaszyfrowanyTekst;
}

licznik = 0;

function szyfrujAesCbc(wczytanyTekst){
  for(var i = 0; i < wczytanyTekst.length; i+=16){
      //pobranie do zmiennej 'text' pierwszych 16 znaków
      fragmentTekstu = wczytanyTekst.substr(i,(i+16));
      //zamiana każdej litery na DEC ASCII, np. a => 97
      bajty = aesjs.utils.utf8.toBytes(fragmentTekstu);
      //zaszyfrowanie tekstu -> AES + ECB
      zaszyfrowaneBajty = mojeCbcSzyfrowanie(bajty);
      //dodanie zaszyfrowanego bloku do pliku wynikowego
      wynikowySzyfrogramCbc[licznik] = zaszyfrowaneBajty;
      licznik++;
  }
}

// rozpoczecie pomiaru czasu wykonania szyfrowania dla AES + CBC - plik 10KB
console.time('Czas-Szyfrowanie-AesCbc-plik-10KB');
szyfrujAesCbc(plik10KB);
console.timeEnd('Czas-Szyfrowanie-AesCbc-plik-10KB');
console.log('\n');

//odszyfrowanie jednego bloku (!) 16 bajtowego
function mojeCbcOdszyfrowanie(tablicaBajtow){
  var odszyfrowanyTekst = new Uint8Array(tablicaBajtow.length);
  var  blok = new Uint8Array(16);
  //petla; dla kazdego bloku tekstu wykona sie tylko raz
  for (var i = 0; i < tablicaBajtow.length; i += 16) {
    //przekopiowanie tablicy zaszyfrowanych bajtow do pojedynczego bloku
    blok = tablicaBajtow;
    blok = mojAes.decrypt(blok);
    for (var j = 0; j < 16; j++) {
      odszyfrowanyTekst[i + j] = blok[j] ^ ostatniBlokSzyfrujacy[j];
    }
    ostatniBlokSzyfrujacy = tablicaBajtow;
  }
  return odszyfrowanyTekst;
}

function deszyfrujAesCbc(tekstZaszyfrowany){
  for(var i = 0; i < tekstZaszyfrowany.length; i++){
      //odszyfrowanie fragmentu - tablica bajtów
      fragmentOdszyfrowany = mojeCbcOdszyfrowanie(tekstZaszyfrowany[i]);
      //dodanie odszyfrowanego (już w znakach) fragmentu do zmiennej wynikowej
      odszyfrowanyTekst += aesjs.utils.utf8.fromBytes(fragmentOdszyfrowany);
  }
}

//rozpoczecie pomiaru czasu wykonania odszyfrowania AES + CBC - plik 10KB
console.time('Czas-Deszyfrowanie-AesCbc-plik-10KB');
deszyfrujAesCbc(wynikowySzyfrogramCbc);
console.timeEnd('Czas-Deszyfrowanie-AesCbc-plik-10KB');
console.log('\n');
