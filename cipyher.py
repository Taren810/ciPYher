''' Schema Input:
-1 cipher
-2 key key2 key3
-3 testo da cifrare

cipher validi:
"caesar" (sostituzione semplice, l'alfabeto viene fatto scorrere di "key" lettere. "key" è un intero)
"vigenere" (sostituzione polialfabetica, la chiave viene addizionata ripetutamente al testo. "key" è una stringa)
"railfence" (trasposizione, la chiave indica l'altezza della griglia su cui il "testo" viene disposto a formare un zigzag. "key" è un intero)
"atbash" (sostituzione semplice, l'alfabeto viene "capovolto". Manca di una qualsiasi chiave)
"autokey" (sostituzione polialfabetica, la chiave è composta da "key" seguita dal "testo", la chiave viene addizionata al testo. "key" è una stringa)
"columnar_transposition" (trasposizione, ad ogni lettera della chiave è legata una colonna del testo, la chiave viene in seguito riordinata in ordine alfabetico. "key" è una stringa)
-"double_transportation"- (trasposizione, come "columnar_transposition" ma con due chiavi. "key" e "key2" sono stringhe, il loro prodotto deve essere maggiore o uguale alla lunghezza del testo)
"A1Z26" (sostituzione semplice, ogni lettera è sostituita con la sua posizione nell'alfabeto. Manca di una qualsiasi chiave)
"trithemius" (sostituzione polialfabetica, ad ogni lettera l'alfabeto cifrato scorre di 1 posizione)
-"playfair"- (sostituzione bigramma, attraverso una tabella 5x5 ogni coppia di lettere viene cifrata. "key" è una stringa, "key2" è la lettera mancante nella tabella e non può essere presente nel testo, "key3" è la lettera con cui vengono riempiti alcuni vuoti)
"morse" (sostituzione semplice, ogni lettera è una sequenza di punti e linee. Manca di qualsiasi chiave)
"morbit" (sostituzione bigramma, ssovra-crittografia del morse. "key" è una stringa numerica)
"schnappsidee" (sostituzione inefficiente, stupida e poco economica, risulta uguale al vigenere. "key" è una stringa numerica di un numero di lettere pari)
"chaocipher" (sostituzione polialfabetica, complessa ed eseguita attraverso due dischi interconnesi rotanti su cui è disposto l'alfabeto. "key" e "key2" sono stringhe che rappresentano l'ordine iniziale dell'alfabeto dei due dischi)

per la decifrazione va aggiunto "dec_" prima del codice del cipher, il testo deve essere il testo cifrato e le chiavi devono essere le stesse con cui è stato cifrato



POLYBIUS SQUARE/CUBE TO IMPLEMENT

'''

import sys, unicodedata, random, time, math

########################################################################### Funzioni per le Ripetizioni del Criptaggio

def SIM_SUB(testo, alfa, beto):
    codice = []
    for i in range(0, len(testo)):
        let = alfa.index(testo[i])
        codice.append(beto[let])
    return codice
        
########################################################################### Sotto-Funzioni di Criptaggio per Cipyher:

def A1Z26(cipher, testo, alfa):
    codice = []
    beto = []
    for i in range(1, len(alfa)+1):
        beto.append(i)
    if cipher == "A1Z26": 
        codice = SIM_SUB(testo, alfa, beto)
    else:
        T = testo.split("-")
        codice = SIM_SUB(T, beto, alfa)

    return ("".join(codice))
    
def AFFINE(cipher, key, key2, testo, alfa):
    beto = []
    codice = []

    for i in range(0, len(alfa)):
        beto.append(alfa[(i*key+key2)%len(alfa)])

    if cipher == "affine":
        codice = SIM_SUB(testo, alfa, beto)
    else:
        codice = SIM_SUB(testo, beto, alfa)
    
    return ("".join(codice))

def ATBASH(testo, alfa):
    codice = []
    beto = alfa.copy()

    for i in range(0, len(alfa)):
        beto.insert(i, beto.pop(len(alfa)-1))

    codice = SIM_SUB(testo, alfa, beto)

    return ("".join(codice))

def AUTOKEY(cipher, key, testo, alfa):
    codice = []
    if cipher == "autokey":
        autokey = []
        for i in range(0, len(key)):
            autokey.append(key[i])
        for i in range(0, len(testo)-len(key)):
            autokey.append(testo[i])

        for i in range(0, len(testo)):
            let = alfa.index(testo[i])
            ind = alfa.index(autokey[i])
            codice.append(alfa[(let+ind)%(len(alfa))])
    
    elif cipher == "dec_autokey":
        autokey = []
        for i in range(0, len(key)):
            autokey.append(key[i])
        
        for i in range(0, len(key)):
            let = alfa.index(testo[i])
            ind = alfa.index(key[i])
            codice.append(alfa[(let-ind)%(len(alfa))])
            autokey.append(codice[i])

        for i in range(len(key), len(testo)):
            let = alfa.index(testo[i])
            ind = alfa.index(autokey[i])
            codice.append(alfa[(let-ind)%(len(alfa))])
            autokey.append(codice[i])

    return ("".join(codice))

def BIFID(cipher, key, testo, alfa):
    matrix = POLYBIUS_SQUARE(alfa, key)
    cooy = []
    coox = []
    for i in range(0, len(testo)):
        for y in range(0, key):
            for x in range(0, key):
                if testo[i] == matrix[y][x]:
                    cooy.append(y)
                    coox.append(x)

    codice = cooy+coox
    dodice = []
    if cipher == "bifid":                
        for i in range(0, len(codice)//2):
            coo = [codice[i*2], codice[i*2+1]]
            dodice.append(matrix[int(coo[0])][int(coo[1])])
    else:
        cooyD = []
        cooxD = []
        posy = 0
        posx = 0
        for i in range(0, len(codice)//2):
            if i%2 == 0:
                cooyD.append(cooy[posy])
                posy += 1
            else:
                cooyD.append(coox[posx])
                posx += 1
        for i in range(len(codice)//2, len(codice)):
            if i%2 == 0:
                cooxD.append(cooy[posy])
                posy += 1
            else:
                cooxD.append(coox[posx])
                posx += 1

        for i in range(0, len(codice)//2):
            dodice.append(matrix[int(cooyD[i])][int(cooxD[i])])

    return ("".join(dodice))

def BIT_NOT(testo):
    codice = []
    for i in range(0, len(testo)):
        codice.append(~ord(testo[i]))

    for i in range(0, len(testo)):
        codice[i] = chr(codice[i]%110000)

    return ("".join(codice))

def BIT_XOR(key, testo):
    codice = []

    for i in range(0, len(testo)):
        codice.append(ord(testo[i])^ord(key[i%len(key)]))

    for i in range(0, len(testo)):
        codice[i] = chr(codice[i])
        
    return ("".join(codice))

def BOOK(cipher, key, testo, alfa):
    codice = []
    beto = []
    for i in range(0, len(alfa)):
        beto.append([])
    for i in range(0, len(key)):
        let = alfa.index(key[i][0])
        beto[let].append(i)

    if cipher == "book":
        for i in range(0, len(testo)):
            let = alfa.index(testo[i])
            random.seed(time.time())
            use = random.randint(0, len(beto[let])-1)
            codice.append(str(beto[let][use]))
    else:
        testo = testo.split()
        for i in range(0, len(testo)):
            for j in range(0, len(alfa)):
                if int(testo[i]) in beto[j]:
                    codice.append(alfa[j])
                    break
    
    return ("".join(codice))

def CAESAR(cipher, key, testo, alfa):
    codice = []
    beto = alfa.copy()
    for i in range(0, int(key)):
        if cipher == "caesar":
            beto.insert(0, beto.pop(len(alfa)-1))
        else:
            beto.insert(len(alfa)-1, beto.pop(0))

    codice = SIM_SUB(testo, alfa, beto)
    return ("".join(codice))

def CHAOCIPHER(cipher, key, key2, testo, alfa):
    beto_sx = []
    beto_dx = []
    codice = []

    for i in range(0, len(alfa)):
        beto_sx.append(key[i])
        beto_dx.append(key2[i])

    for i in range(0, len(testo)):
        if cipher == "chaocipher":
            rot = beto_dx.index(testo[i])
        else:
            rot = beto_sx.index(testo[i])

        for j in range(0, rot):
            beto_dx.insert(len(alfa)-1, beto_dx.pop(0))
            beto_sx.insert(len(alfa)-1, beto_sx.pop(0))

        if cipher == "chaocipher":
            codice.append(beto_sx[0])
        else:
            codice.append(beto_dx[0])

        beto_sx.insert(int(len(alfa)/2), beto_sx.pop(1))
        beto_dx.insert(len(alfa)-1, beto_dx.pop(0))
        beto_dx.insert(int(len(alfa)/2), beto_dx.pop(2))

    return ("".join(codice))

def COLUMNAR_TRANSPOSITION(cipher, key, testo, alfa):
    codice = []
    if cipher == "columnar_transposition":
        keyN = []
        for i in range(0, len(key)):
            for j in range(0, len(alfa)):
                if key[i] == alfa[j]:
                    keyN.append(j)
                    break

        matrix = []
        for i in range(0, len(key)):
            matrix.append([])

        pos = 0
        for i in range(0, len(testo)):
            matrix[pos].append(testo[i])
            pos+=1
            if pos>=len(key):
                pos = 0

        for i in range(0, len(key)):
            ind = keyN[0]
            for j in range(0, len(keyN)):
                ind = min(ind, keyN[j])
            topop = keyN.index(ind)
            keyN.pop(topop)
            codice.append("".join(matrix[topop]))
            matrix.pop(topop)

    elif cipher == "dec_columnar_transposition":
        keyN = []
        for i in range(0, len(key)):
            for j in range(0, len(alfa)):
                if key[i] == alfa[j]:
                    keyN.append(j)
                    break

        matrix = []
        for i in range(0, len(key)):
            matrix.append([])

        extraN=len(testo)%len(key)
        extraL=list(keyN[0:extraN])
        keyNsort = keyN.copy()
        keyNsort.sort()
        let = 0
        for i in range(0, len(key)):
            matrix[i] = testo[let:(let+int(len(testo)/len(key)))]
            if keyNsort[i] in extraL:
                matrix[i] += testo[let+int(len(testo)/len(key))]
                let+=1
            let += int(len(testo)/len(key))

        newmatrix =[]
        for i in range(0, len(key)):
            ind = keyNsort.index(keyN[i])
            keyNsort[ind] = ""
            newmatrix.append(matrix[ind])

        pos = -1
        for i in range(0, len(testo)):
            if i%len(key)==0:
                pos+=1
            codice.append(newmatrix[i%len(key)][pos])

    return("".join(codice))

def CUSTOM_HOMOPHONIC_SUBSTITUTION(cipher, key, testo, alfa):
    codice = []
    if cipher == "custom_homophonic_substitution":
        for i in range(0, len(testo)):
            let = alfa.index(testo[i])
            random.seed(time.time())
            use = random.randint(0, len(key[let])-1)
            codice.append(key[let][use])

    elif cipher == "dec_custom_homophonic_substitution":
        for i in range(0, len(testo)):
            for j in range(0, len(alfa)):
                if key[j].find(testo[i]) != -1:
                    let = j
                    break
            codice.append(alfa[let])

    return ("".join(codice))

def CUSTOM_HOMOPHONIC_WORD_SUBSTITUTION(cipher, key, testo, alfa):
    codice = []
    for i in range(0, len(testo)):
        let = alfa.index(testo[i])
        random.seed(time.time())
        use = random.randint(0, len(key[let])-1)
        codice.append(key[let][use])

    return (" ".join(codice))

def CUSTOM_SUBSTITUTION(cipher, key, testo, alfa):
    codice = []
    if cipher == "custom_substitution":
        codice = SIM_SUB(testo, alfa, key)  
    elif cipher == "dec_custom_substitution":
        codice = SIM_SUB(testo, key, alfa) 

    return ("".join(codice))

def DERANGED_ALPHABET(key, alfa):
    key = list(key)
    while len(key)>0:
        let = key[len(key)-1]
        alfa.remove(let)
        alfa.insert(0, let)
        for j in range(0, key.count(let)):
            key.remove(let)
    return ("".join(alfa))

def FLIP(testo):
    codice = []
    for i in range(0, len(testo)):
        codice.insert(0, testo[i])

    return ("".join(codice))

def MORBIT(cipher, key, testo, alfa):
    morbit = ["..", ".-", "./", "-.", "--", "-/", "/.", "/-", "//"]
    keyM = []
    codice = []
    for i in range(0, 9):
        keyM.append("")
    for i in range(0, 9):
        keyM[int(key[i])-1] = morbit[i]

    if cipher == "morbit":
        testoM = MORSE("morse", testo, alfa)
        if len(testoM)%2 != 0:
            testoM += "/" 
        for i in range(0, int(len(testoM)/2)):
            bigram = testoM[i*2:i*2+2]
            for j in range(0, 9):
                if bigram == keyM[j]:
                    codice.append(str(j+1))
    else:
        testoM = ""
        for i in range(0, len(testo)):
            testoM += keyM[int(testo[i])-1]

        codice = MORSE("dec_morse", testoM, alfa)

    return ("".join(codice))

def MORSE(cipher, testo, alfa):
    beto = [".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....", "..", ".---", "-.-", ".-..", "--", "-.", "---", ".--.", "--.-", ".-.", "...", "-", "..-", "...-", ".--", "-..-", "-.--", "--.."]
    codice = []

    if cipher == "morse":
        for i in range(0, len(testo)):
            if testo[i]!=" ":
                let = alfa.index(testo[i])
                codice.append(beto[let])
            else:
                codice.append("")

        return ("/".join(codice))
    else:
        T = testo.split("/")
        for i in range(0, len(T)):
            if T[i]!="":
                let = beto.index(T[i])
                codice.append(alfa[let])
            else:
                codice.append(" ")

        return ("".join(codice))

def POLYBIUS_CUBE(alfa, key=3):
    matrix = []
    for i in range(0, key):
        matrix.append([])
        for j in range(0, key):
            matrix[i].append([])
            for k in range(0, key):
                matrix[i][j].append(" ")
    
    if len(alfa)>(key*key*key):
        n = key*key*key
    else:
        n = len(alfa)

    pos = -1
    pos2 = -1
    for i in range(0, n):
        if i%(key*key) == 0:
            pos2 += 1
            pos = -1
        if i%key == 0:
            pos += 1
        matrix[pos2][pos][i%key] = alfa[i]

    return (matrix)

def POLYBIUS_SQUARE(alfa, key=5):
    matrix = []
    for i in range(0, key):
        matrix.append([])
        for j in range(0, key):
            matrix[i].append(" ")
    
    if len(alfa)>(key*key):
        n = key*key
    else:
        n = len(alfa)

    pos = -1
    for i in range(0, n):
        if i%key == 0:
            pos += 1
        matrix[pos][i%key] = alfa[i]

    return (matrix)

def SCHNAPPSIDEE(cipher, key, testo, alfa):
    beto = []
    codice = []

    for i in range(0, len(alfa)):
        beto.append(ord(alfa[i]))
    testo_uni = []
    key_arr = []

    for i in range(0, int(len(key)/2)):
        key_arr.append(int(key[i:i+2]))
    
    if cipher == "schnappsidee":
        for i in range(0, len(testo)):
            let = alfa.index(testo[i])
            testo_uni.append(beto[let])

        for i in range(0, len(testo)):
            x = testo_uni[i]
            y = abs(len(testo)-x)
            j = int(i/2)%(int(len(key)/2))
            codice.append(key_arr[j]*len(alfa)*x*y)

        sys.set_int_max_str_digits(1114111)

        for i in range(0, len(codice)):
            index = int(codice[i])%154998
            codice[i] = chr(index)
    else:
        for i in range(0, len(testo)):
            j = int(i/2)%(int(len(key)/2))
            t = len(testo)
            u = int(ord(testo[i]))
            a = len(alfa)
            x = int((len(testo)+math.sqrt(abs(int((t*t*key_arr[j]*a-4*u)/(key_arr[j]*a)))))/2)
            codice.append(chr(x))            

    return ("".join(codice))

def RADICAL(cipher, testo, alfa):
    codice = []
    beto = []
    for i in range(0, len(alfa)):
        beto.append(alfa[(i*i)%len(alfa)])

    if cipher == "radical":
        codice = SIM_SUB(testo, alfa, beto)
        return ("".join(codice))
    else:
        codice2 = []
        for i in range(0, len(testo)):
            let = alfa.index(testo[i])
            while math.sqrt(let)%1 != 0:
                let += len(alfa)
            codice.append(alfa[int(math.sqrt(let))])
            codice2.append(alfa[int(-math.sqrt(let)%len(alfa))])

        def_codice ="".join(codice)+"\n"+csym()+" "+"".join(codice2)
        return ("".join(def_codice))

def RAILFENCE(cipher, key, testo):
    codice = []
    if cipher == "railfence":
        rail = []
        for i in range(0, int(key)):
            rail.append([])
            for j in range(0, len(testo)):
                rail[i].append(" ")
        ud = 0
        pos = 0
        for i in range(0, len(testo)):
            rail[pos][i] = testo[i]
            if (i%(len(rail)-1)==0) and (i != 0):
                if ud == 0:
                    ud = 1
                else:
                    ud = 0
            if ud == 0:
                pos += 1
            else:
                pos-= 1

        for i in range(0, len(rail)):
            codice.append("".join(rail[i]))

        return ("".join(codice).replace(' ', ''))
    
    elif cipher == "dec_railfence":
        rail = []
        for i in range(0, int(key)):
            rail.append([])
            for j in range(0, len(testo)):
                rail[i].append(" ")
        ud = 0
        pos = 0
        for i in range(0, len(testo)):
            rail[pos][i] = 0
            if (i%(len(rail)-1)==0) and (i != 0):
                if ud == 0:
                    ud = 1
                else:
                    ud = 0
            if ud == 0:
                pos += 1
            else:
                pos-= 1

        start = 0
        for j in range(0, key):
            for i in range(0, len(testo)):
                if rail[j][i]==0:
                    rail[j][i]=testo[start]
                    start+=1
        
        for i in range(0, len(testo)):
            for j in range(0, key):
                if rail[j][i]!=" ":
                    codice.append(str(rail[j][i]))
        
        return ("".join(codice))
    
def TRIFID(cipher, key, testo, alfa):
    matrix = POLYBIUS_CUBE(alfa, key)
    cooy = []
    coox = []
    cooz = []
    for i in range(0, len(testo)):
        for z in range(0, key):
            for y in range(0, key):
                for x in range(0, key):
                    if testo[i] == matrix[z][y][x]:
                        cooz.append(z)
                        cooy.append(y)
                        coox.append(x)

    codice = cooz+cooy+coox
    dodice = []
    if cipher == "trifid":                
        for i in range(0, len(codice)//2):
            coo = [codice[i*3], codice[i*3+1], codice[i*3+2]]
            dodice.append(matrix[int(coo[0])][int(coo[1])][int(coo[2])])
    else:
        coozD = []
        cooyD = []
        cooxD = []
        posz = 0
        posy = 0
        posx = 0
        for i in range(0, len(codice)//3):
            if i%3 == 0:
                coozD.append(cooz[posz])
                posz += 1
            elif i%2 == 0:
                coozD.append(cooy[posy])
                posy += 1
            else:
                coozD.append(coox[posx])
                posx += 1
        for i in range(len(codice)//3, (len(codice)//3)*2):
            if i%3 == 0:
                cooyD.append(cooz[posz])
                posz += 1
            elif i%2 == 0:
                cooyD.append(cooy[posy])
                posy += 1
            else:
                cooyD.append(coox[posx])
                posx += 1
        for i in range((len(codice)//3)*2, len(codice)):
            if i%3 == 0:
                cooxD.append(cooz[posz])
                posz += 1
            elif i%2 == 0:
                cooxD.append(cooy[posy])
                posy += 1
            else:
                cooxD.append(coox[posx])
                posx += 1

        for i in range(0, len(codice)//3):
            dodice.append(matrix[int(coozD[i])][int(cooyD[i])][int(cooxD[i])])

    return ("".join(dodice))

def TRITHEMIUS(cipher, testo, alfa):
    codice = []
    beto = alfa.copy()
    for i in range(0, len(testo)):
        if cipher == "trithemius":
            beto.append(beto.pop(0))
        else:
            beto.insert(0, beto.pop(len(alfa)-1))
        let = alfa.index(testo[i])
        codice.append(beto[let])

    return ("".join(codice))

def VIGENERE(cipher, key, testo, alfa):
    codice = []
    beto = alfa.copy()
    key = key.upper()
    for i in range(0, len(testo)):
        letk = key[i%len(key)]
        ind = alfa.index(letk)
        if cipher == "dec_vigenere":
            ind = -ind
        for j in range(0, len(alfa)):
            beto[j] = alfa[(j+ind)%(len(alfa))]

        let = alfa.index(testo[i])
        codice.append(beto[let])

    return ("".join(codice))

#################################################################################### Discriminante (?)

def CIPYHER(cipher, testo, key, key2, key3, alfa):

    if not cipher in ["morse", "morbit", "dec_book", "bit_xor", "dec_bit_xor"]:
        testo = testo.replace(" ", "")

    if cipher == "deranged_alphabet":
        return DERANGED_ALPHABET(key, alfa)
    
    elif cipher in ["caesar", "dec_caesar"]:
        return CAESAR(cipher, key, testo, alfa)
        
    elif cipher in ["custom_substitution", "dec_custom_substitution"]:
        return CUSTOM_SUBSTITUTION(cipher, key, testo, alfa)
    
    elif cipher in ["custom_homophonic_substitution", "dec_custom_homophonic_substitution"]:
        return CUSTOM_HOMOPHONIC_SUBSTITUTION(cipher, key, testo, alfa)
    
    elif cipher in ["custom_homophonic_word_substitution", "dec_custom_homophonic_word_substitution"]:
        return CUSTOM_HOMOPHONIC_WORD_SUBSTITUTION(cipher, key, testo, alfa)
        # missing dec_

    elif cipher in ["vigenere", "dec_vigenere"]:
        return VIGENERE(cipher, key, testo, alfa)

    elif cipher in ["atbash", "dec_atbash"]:
        return ATBASH(testo, key)

    elif cipher in ["railfence", "dec_railfence"]:
        return RAILFENCE(cipher, key, testo)

    elif cipher in ["autokey", "dec_autokey"]:
        return AUTOKEY(cipher, key, testo, alfa)

    elif cipher in ["columnar_transposition", "dec_columnar_transposition"]:
        return COLUMNAR_TRANSPOSITION(cipher, key, testo, alfa)

    elif cipher == "double_transposition":
        for f in range(0, 2):
            keyN = []
            for i in range(0, len(key)):
                for j in range(0, len(alfa)):
                    if key[i] == alfa[j]:
                        keyN.append(j)
                        break

            matrix = []
            for i in range(0, len(key)):
                matrix.append([])

            pos = 0
            for i in range(0, len(testo)):
                matrix[pos].append(testo[i])
                pos+=1
                if pos>=len(key):
                    pos = 0

            print(matrix)

            for i in range(0, len(key)):
                ind = keyN[0]
                for j in range(0, len(keyN)):
                    ind = min(ind, keyN[j])
                topop = keyN.index(ind)
                keyN.pop(topop)
                print(topop)
                print(matrix)
                codice.append("".join(matrix[topop]))
                print(codice)
                matrix.pop(topop)

            if f == 0:
                testo = codice
                codice = []
                key = key2

        return ("".join(codice))

    elif cipher in ["A1Z26", "dec_A1Z26"]:
        return A1Z26(cipher, testo, alfa)
        
    elif cipher in ["book", "dec_book"]:
        return BOOK(cipher, key, testo, alfa)

    elif cipher in ["trithemius", "dec_trithemius"]:
        return TRITHEMIUS(cipher, testo, alfa)

    elif cipher == "playfair":
        beto = alfa.copy()
        mat = [[], [], [], [], []]
        beto.remove(key2)
        for i in range(0, 25):
            if len(key)>i:
                if ((not (key[i] in mat[0])) and (not (key[i] in mat[1])) and (not (key[i] in mat[2])) and (not (key[i] in mat[3])) and (not (key[i] in mat[4]))):
                    mat[int(i/5)].append(key[i])
                    beto.remove(key[i])
                else:
                    mat[int(i/5)].append(beto[0])
                    beto.pop(0)
            else:
                mat[int(i/5)].append(beto[0])
                beto.pop(0)

        testo_c = testo

        while len(testo_c)>2:
            digram = []
            digram.append(testo_c[0])
            digram.append(testo_c[1])
            testo_c = testo_c[2:]

            for i in range(0, 5):
                for j in range(0, 5):
                    if mat[i][j] == digram[0]:
                        coo0 = [i, j]
            for i in range(5):
                for j in range(5):
                    if mat[i][j] == digram[1]:
                        coo1 = [i, j]

            if coo0[0]==coo1[0]:
                if coo0[1]==coo1[1]:
                    testo_c = digram[0] + key3 + digram[1] + testo_c
                else:
                    codice.append(mat[coo0[0]][(coo0[1]+1)%5])
                    codice.append(mat[coo1[0]][(coo1[1]+1)%5])
            else:
                if coo0[1]==coo1[1]:
                    codice.append(mat[(coo0[0]+1)%5][coo0[1]])
                    codice.append(mat[(coo1[0]+1)%5][coo1[1]])
                else:
                    codice.append(mat[coo0[0]][coo1[1]])
                    codice.append(mat[coo1[0]][coo0[1]])

            if len(testo_c)==1:
                testo_c = testo_c + key3

        return ("".join(codice)) 

    elif cipher in ["morse", "dec_morse"]:
        return MORSE(cipher, testo, alfa)

    elif cipher in ["morbit", "dec_morbit"]:
        return MORBIT(cipher, key, testo, alfa)

    elif cipher in ["schnappsidee", "dec_schnappsidee"]:
        return SCHNAPPSIDEE(cipher, key, testo, alfa)

    elif cipher in ["chaocipher", "dec_chaocipher"]:
        return CHAOCIPHER(cipher, key, key2, testo, alfa)
    
    elif cipher in ["bit_xor", "dec_bit_xor"]:
        return BIT_XOR(key, testo)
    
    elif cipher in ["bit_not", "dec_bit_not"]:
        return BIT_NOT(testo)
    
    elif cipher in ["affine", "dec_affine"]:
        return AFFINE(cipher, key, key2, testo, alfa)
    
    elif cipher in ["radical", "dec_radical"]:
        return RADICAL(cipher, testo, alfa)
    
    elif cipher in ["flip", "dec_flip"]:
        return FLIP(testo)
    
    elif cipher in ["polybius_square"]:
        codice = []
        matrix = POLYBIUS_SQUARE(alfa, key)
        for i in range(0, key):
            codice.append("".join(matrix[i]))
        return (("\n"+csym()+" ").join(codice))
    
    elif cipher in ["polybius_cube"]:
        codice = []
        matrix = POLYBIUS_CUBE(alfa, key)
        for i in range(0, key):
            for j in range(0, key):
                codice.append("".join(matrix[i][j]))
        return (("\n"+csym()+" ").join(codice))
    
    elif cipher in ["bifid", "dec_bifid"]:
        return BIFID(cipher, key, testo, alfa)
    
    elif cipher in ["trifid", "dec_trifid"]:
        return TRIFID(cipher, key, testo, alfa)

#################################################################################### Interfaccia

def csym(cool = ["%", "$", "£", "&", "#", "@", "=", "0", "§", "<", ">"]):
    random.seed(time.time())
    sym = random.randint(0, len(cool)-1)
    coolsym = cool[sym]
    return (coolsym+"|")

def choice_viewer(preview, tag, tagP):
    pre = 0
    for i in range(0, len(preview)+len(tag)):
        if i in tagP:
            ind = tagP.index(i)
            print(csym(),"   ", tag[ind],":", sep="")
        else:
            print(csym(),"  ", pre, preview[pre])
            pre+=1

def alfa_choose():
    eror = True
    first = True
    while eror == True:
        eror = False
        print(csym(["?"]),"Choose a supported alphabet:")
        if first:
            preview = ["latin_upper", "latin_lower", "bicameral_latin", "mixed_bicameral_latin", "latin_upper_without_J", "latin_upper_with_numbers", "latin_lower_with_numbers", "bicameral_latin_with_numbers", "mixed_bicameral_latin_with_numbers", "greek_upper", "greek_lower", "bicameral_greek", "mixed_bicameral_greek", "numbers_0_9", "numbers_1_10", "numbers_0_25", "numbers_1_26", "deranged_alphabet", "unicode", "custom"]
            first = False
        choice_viewer(preview, ["latin", "greek", "numerical", "other"], [0, 10, 15, 20])
        print(csym(["="]), ">",end=" ")
        alfalfa = input().strip().lower()
        if alfalfa.isnumeric():
            if int(alfalfa)<len(preview):
                alfalfa = preview[int(alfalfa)]
            else:
                print(csym(["!"]),"Input not valid: cipher not found")
                eror = True
                continue

        if alfalfa in ["std", "latin_upper"]:
            alfa = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
        elif alfalfa in ["latin_lower"]:
            alfa = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
        elif alfalfa in ["bicameral_latin", "latin_both"]:
            alfa = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
        elif alfalfa in ["mixed_bicameral_latin", "latin_both_mixed"]:
            alfa = ["A", "a", "B", "b", "C", "c", "D", "d", "E", "e", "F", "f", "G", "g", "H", "h", "I", "i", "J", "j", "K", "k", "L", "l", "M", "m", "N", "n", "O", "o", "P", "p", "Q", "q", "R", "r", "S", "s", "T", "t", "U", "u", "V", "v", "W", "w", "X", "x", "Y", "y", "Z", "z"]
        elif alfalfa in ["latin_upper_without_J"]:
            alfa = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
        elif alfalfa in ["latin_upper_with_numbers"]:
            alfa = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        elif alfalfa in ["latin_lower_with_numbers"]:
            alfa = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        elif alfalfa in ["bicameral_latin_with_numbers", "latin_both_number"]:
            alfa = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        elif alfalfa in ["mixed_bicameral_latin_with_numbers", "latin_both_mixed_number"]:
            alfa = ["A", "a", "B", "b", "C", "c", "D", "d", "E", "e", "F", "f", "G", "g", "H", "h", "I", "i", "J", "j", "K", "k", "L", "l", "M", "m", "N", "n", "O", "o", "P", "p", "Q", "q", "R", "r", "S", "s", "T", "t", "U", "u", "V", "v", "W", "w", "X", "x", "Y", "y", "Z", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        elif alfalfa in ["greek_upper"]:
            alfa = ["α", "β", "γ", "δ", "ε", "ζ", "η", "θ", "ι", "κ", "λ", "μ", "ν", "ξ", "ο", "π", "ρ", "σ", "ς", "τ", "υ", "φ", "χ", "ψ", "ω"]
        elif alfalfa in ["greek_lower"]:
            alfa = ["Α", "Β", "Γ", "Δ", "Ε", "Ζ", "Η", "Θ", "Ι", "Κ", "Λ", "Μ", "Ν", "Ξ", "Ο", "Π", "Ρ", "Σ", "Τ", "Υ", "Φ", "Χ", "Ψ", "Ω"]
        elif alfalfa in ["bicameral_greek", "greek_both"]:
            alfa = ["Α", "Β", "Γ", "Δ", "Ε", "Ζ", "Η", "Θ", "Ι", "Κ", "Λ", "Μ", "Ν", "Ξ", "Ο", "Π", "Ρ", "Σ", "Τ", "Υ", "Φ", "Χ", "Ψ", "Ω", "α", "β", "γ", "δ", "ε", "ζ", "η", "θ", "ι", "κ", "λ", "μ", "ν", "ξ", "ο", "π", "ρ", "σ", "ς", "τ", "υ", "φ", "χ", "ψ", "ω"]
        elif alfalfa in ["mixed_bicameral_greek", "greek_both_mixed"]:
            alfa = ["Α", "α", "Β", "β", "Γ", "γ", "Δ", "δ", "Ε", "ε", "Ζ", "ζ", "Η", "η", "Θ", "θ", "Ι", "ι", "Κ", "κ", "Λ", "λ", "Μ" "μ", "Ν", "ν", "Ξ", "ξ", "Ο", "ο", "Π", "π", "Ρ", "ρ", "Σ", "σ", "ς", "Τ", "τ", "Υ", "υ", "Φ", "φ", "Χ", "χ", "Ψ", "ψ", "Ω", "ω"]
        elif alfalfa in ["numbers_0_9", "numerical", "digits"]:
            alfa = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        elif alfalfa in ["numbers_1_10"]:
            alfa = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
        elif alfalfa in ["numbers_0_25"]:
            alfa = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P"]
        elif alfalfa in ["numbers_1_26"]:
            alfa = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q"]
        elif alfalfa in ["deranged_alphabet"]:
            alfa = alfa_choose()
            key = input_key("deranged_alphabet", alfa)[0]
            alfa = list(DERANGED_ALPHABET(key, alfa))
        elif alfalfa == "unicode":
            alfa = ["everything?"]
        elif alfalfa in ["custom"]:
            print(csym(["?"]),"Input a custom alphabet:")
            print(csym(["="]), ">", end=" ")
            alfa = list(input().strip())
        else:
            eror = True
            print(csym(["!"]),"Input not valid: alphabet not found")
    
    return alfa

def cipher_choose():
    eror = True
    first = True
    while eror == True:
        print(csym(["?"]),"Choose a supported cipher (to decipher input the opposite of the value or add 'dec_' to the string):")
        preview = ["custom_substitution", "A1Z26", "affine", "atbash", "caesar", "morse", "autokey", "chaocipher", "radical", "trithemius", "vigenere", "bifid", "trifid", "custom_homophonic_substitution", "book", "custom_homophonic_word_substitution", "columnar_transposition", "double_transportation", "flip", "playfair", "railfence", "morbit", "bit_xor", "bit_not", "schnappsidee", "deranged_alphabet", "polybius_square", "polybius_cube"]
        if first:
            choice_viewer(preview, ["monoalphabetic substitution", "polyalphabetic substitution", "polygraphic substitution", "homophonic substitution", "transposition", "bit-wise substitution", "other"], [0, 7, 13, 16, 20, 26, 31])
            first = False
        print(csym(["="]), ">",end=" ")
        cipher = input().strip().lower()
        if cipher[0] == "-":
            cipher = cipher[1:]
            if cipher.isnumeric():
                if int(cipher)<=len(preview):
                    cipher = "dec_" + preview[int(cipher)]
                else:
                    print(csym(["!"]),"Input not valid: cipher not found")
                    continue
        elif cipher.isnumeric():
            if int(cipher)<len(preview):
                cipher = preview[int(cipher)]
            else:
                print(csym(["!"]),"Input not valid: cipher not found")
                continue
        if cipher in ["custom_substitution", "A1Z26", "affine", "atbash", "caesar", "morse", "autokey", "chaocipher", "radical", "trithemius", "vigenere", "bifid", "trifid", "custom_homophonic_substitution", "book", "custom_homophonic_word_substitution", "columnar_transposition", "double_transportation", "flip","playfair", "railfence", "morbit", "bit_xor", "bit_not", "schnappsidee", "deranged_alphabet", "polybius_square", "polybius_cube", "dec_custom_substitution", "dec_A1Z26", "dec_affine", "dec_atbash", "dec_caesar", "dec_morse", "dec_autokey", "dec_chaocipher", "dec_radical", "dec_trithemius", "dec_vigenere", "dec_bifid", "dec_trifid", "dec_custom_homophonic_substitution", "dec_book", "dec_custom_homophonic_word_substitution", "dec_columnar_transposition", "dec_double_transportation", "dec_flip", "dec_playfair", "dec_railfence", "dec_morbit", "dec_bit_xor", "dec_bit_not", "dec_schnappsidee", "deranged_alphabet", "polybius_square", "polybius_cube"]:
            eror = False
        else:
            print(csym(["!"]),"Input not valid: cipher not found")

    return cipher

def input_key(cipher, alfa):
    key, key2, key3 = "NA", "NA", "NA"
    eror = True
    while eror == True:
        if cipher in ["caesar", "dec_caesar", "railfence", "dec_railfence", "polybius_square", "polybius_cube", "bifid", "dec_bifid", "trifid", "dec_trifid"]:
            print(csym(["?"]),"Input the key (must be an integer):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if key.isnumeric():
                key = int(key)
                eror = False
            else:
                print(csym(["!"]),"Input not valid: not numeric")
        elif cipher in ["deranged_alphabet", "vigenere", "dec_vigenere", "autokey", "dec_autokey", "columnar_transposition", "dec_columnar_transposition"]:
            print(csym(["?"]),"Input the key (must be an alphabetic string of letters present in the chosen alphabet):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if isinstance(key, str):
                eror = False
                for i in range(0, len(key)):
                    if key[i] not in alfa:
                        eror = True
                        print(csym(["!"]), "Input not valid: cointains a character not in the chosen alphabet")
                        break
            else:
                print(csym(["!"]),"Input not valid: not a string")
        elif cipher in ["morbit", "dec_morbit"]:
            print(csym(["?"]),"Input the key (must be a numeric string containing all the 1-9 digits):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if isinstance(key, str):
                if key.isnumeric():
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not numeric")
            else:
                print(csym(["!"]),"Input not valid: not a string")
        elif cipher in ["schnappsidee", "dec_schnappsidee"]:
            print(csym(["?"]),"Input the key (must be a numeric string of even lenght):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if isinstance(key, str):
                if key.isnumeric() and (len(key)%2) == 0:
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not numeric or of even lenght")
            else:
                print(csym(["!"]),"Input not valid: not a string")
        elif cipher in ["custom_substitution", "dec_custom_substitution"]:
            print(csym(["?"]),"Input the custom alphabet (must be a", len(alfa), "character long string):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if isinstance(key, str):
                if len(key) == len(alfa):
                    key = list(key)
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not", len(alfa), "character")
            else:
                print(csym(["!"]),"Input not valid: not a string")
        elif cipher in ["custom_homophonic_substitution", "dec_custom_homophonic_substitution"]:
            print(csym(["?"]),"Input the key (must be a list of", len(alfa), "unique elements, every character of an element is a possible substitution for the letter)")
            print(csym(["="]), ">", end=" ")
            key = input().strip().split()
            if len(key) == len(alfa):
                eror = False
                used = []
                for i in range(0, len(alfa)):
                    if eror == True:
                        break
                    for j in range(0, len(key[i])):
                        if eror == True:
                            break
                        for k in range(0, len(used)):
                            if key[i][j] == used[k]:
                                eror = True
                                print(csym(["!"]),"Input not valid: character", used[k], "is used multiple times")
                                break
                        used.append(key[i][j])
            else:
                print(csym(["!"]),"Input not valid: not", len(alfa), "elements")
        elif cipher in ["chaocipher", "dec_chaocipher"]:
            print(csym(["?"]),"Input the first key (must be a", len(alfa), "letter long string containing all the letters of the chosen alphabet):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if isinstance(key, str):
                if len(key) == len(alfa):
                    eror = False
                    for i in range(0, len(alfa)):
                        if  key.find(alfa[i])==-1:
                            print(csym(["!"]),"Input not valid: missing the letter", alfa[i])
                            eror = True
                            break
                else:
                    print(csym(["!"]),"Input not valid: not", len(alfa), "characters")
            else:
                print(csym(["!"]),"Input not valid: not a string")
            if eror == True:
                continue    
            
            print(csym(["?"]),"Input the second key (must be a", len(alfa), "letter long string containing all the letters of the chosen alphabet):")
            print(csym(["="]), ">", end=" ")
            key2 = input().strip()
            if isinstance(key2, str):
                if len(key2) == len(alfa):
                    eror = False
                    for i in range(0, len(alfa)):
                        if  key2.find(alfa[i])==-1:
                            print(csym(["!"]),"Input not valid: missing the letter", alfa[i])
                            eror = True
                            break
                else:
                    print(csym(["!"]),"Input not valid: not", len(alfa), "characters")
            else:
                print(csym(["!"]),"Input not valid: not a string")
        elif cipher in ["double_transposition", "dec_double_transposition"]:
            print(csym(["?"]),"Input the first key (must be an alphabetic string, remember that the the product of the length of the two keys must be greater than the length of the text):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if isinstance(key, str):
                if key.isalpha():
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not alphabetic")
                    continue
            else:
                print(csym(["!"]),"Input not valid: not a string")
                continue
            print(csym(["?"]),"Input the second key (must be an alphabetic string):")
            print(csym(["="]), ">", end=" ")
            key2 = input().strip()
            if isinstance(key2, str):
                if key2.isalpha():
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not alphabetic")
            else:
                print(csym(["!"]),"Input not valid: not a string")
        elif cipher in ["book", "dec_book"]:
            print(csym(["?"]),"Input the key (must be a text of alphabetic strings):")
            print(csym(["="]), ">", end=" ")
            key = input().strip().split()
            eror = False
            for i in range(0, len(KEY)):
                if not key[i].isalpha():
                    eror = True
                    print(csym(["!"]),"Input not valid: not alphabetic")
                    break
        elif cipher in ["bit_xor", "dec_bit_xor"]:
            print(csym(["?"]),"Input the key (must be a string):")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            eror = False
        elif cipher in ["affine"]:
            print(csym(["?"])," Input the first key (must be an integer and a coprime of ", len(alfa),"):", sep="")
            print(csym(["="]), ">", end=" ")
            key = input().strip()
            if key[0] != "-":
                if key.isnumeric():
                    key = int(key)
                    if math.gcd(key, len(alfa)) == 1:
                        eror = False
                    else:
                        print(csym(["!"]),"Input not valid: not coprime")
                        continue
                else:
                    print(csym(["!"]),"Input not valid: not numeric")
                    continue
            else:
                key = key[1:]
                if key.isnumeric():
                    key = -int(key)
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not numeric")
                    continue
            print(csym(["?"]),"Input the second key (must be an integer):")
            print(csym(["="]), ">", end=" ")
            key2 = input().strip()
            if key2[0] != "-":
                if key2.isnumeric():
                    key2 = int(key2)
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not numeric")
            else:
                key2 = key2[1:]
                if key2.isnumeric():
                    key2 = -int(key2)
                    eror = False
                else:
                    print(csym(["!"]),"Input not valid: not numeric")
        elif cipher in ["custom_homophonic_word_substitution", "dec_custom_homophonic_word_substitution"]:
            print(csym(["?"]),"Input the key (must be a list of", len(alfa), "lists of unique strings separated by '|' ):")
            print(csym(["="]), ">", end=" ")
            key = input().strip().split("|")
            kLen = len(key)
            for i in range(0, kLen):
                key[i] = key[i].strip().split()
            if len(key) == len(alfa):
                eror = False
                used = []
                for i in range(0, len(alfa)):
                    if eror == True:
                        break
                    for j in range(0, len(key[i])):
                        if eror == True:
                            break
                        for k in range(0, len(used)):
                            if key[i][j] == used[k]:
                                eror = True
                                print(csym(["!"]),"Input not valid: string", used[k], "is used multiple times")
                                break
                        used.append(key[i][j])
            else:
                print(csym(["!"]),"Input not valid: not", len(alfa), "elements")
        else: #cipher in ["morse", "atbash", "trithemius", "flip", "dec_flip": "dec_morse", "dec_atbash", "dec_trithemius", "bit_not", "dec_bit_not", "radical", "dec_radical"]:
            eror = False

    return (key, key2, key3)

def input_text(cipher, alfa):
    eror = True
    while eror == True:
        if cipher in ["deranged_alphabet", "polybius_square", "polybius_cube"]:
            eror = False
            return ""
        elif alfa == "unicode":
            print(csym(),"Input the text:")
            print(csym(), ">", end=" ")
            testo = input().strip()
            eror = False
            return testo
        else:
            print(csym(),"Input the text:")
            print(csym(), ">", end=" ")
            testo = input().strip()
            eror = False
            for i in range(0, len(testo)):
                if testo[i] not in alfa:
                    eror = True
                    print(csym(["!"]), "Input not valid: cointains a character not in the chosen alphabet")
                    continue
            return testo
            

banner = [
    "|-------------------|---------------------------------------------------------------------|-------------------|",
    "|-----###---###-----|--##########--##--######----##----##--##-----##--########--######----|-----###---###-----|",
    "|--###############--|--##########--##--########--##----##--##-----##--########--########--|--###############--|",
    "|--###############--|--##----------##--##----##--##----##--##-----##--##--------##----##--|--###############--|",
    "|-----###---###-----|--##----------##--##----##--###--###--#########--#######---##----##--|-----###---###-----|",
    "|-----###---###-----|--##----------##--########---######---#########--#######---########--|-----###---###-----|",
    "|--###############--|--##----------##--######-------##-----##-----##--##--------######----|--###############--|",
    "|--###############--|--##########--##--##-----------##-----##-----##--########--##---##---|--###############--|",
    "|-----###---###-----|--##########--##--##-----------##-----##-----##--########--##----##--|-----###---###-----|",
    "|-------------------|---------------------------------------------------------------------|-------------------|"
]

''' Banner "Font" Randomizer
for i in range(0, len(banner)):
    for j in range(0, len(banner[i])):
        if banner[i][j] == "#":
            banner[i] = banner[i][:j]+csym(["#"])+banner[i][j+1:]
'''

for i in range(0, len(banner)):
    print(csym(),banner[i],csym(),sep="")
    
print(csym())
print(csym())
print(csym())
escape = False
while escape == False:
    print(csym(),"Select input/output mode:")
    print(csym(), ">", end=" ")
    #io = input().strip()
    print("console")
    io = "console"
    if io == "txt":
        sys.stdin = open('input.txt')
        sys.stdout = open('output.txt', 'w')
        CIPHER = input().strip()
        KEY, KEY2, KEY3 = input().strip().split()
        ALFA = input().strip()
        TESTO = input().strip()
        print(CIPYHER(CIPHER, TESTO, KEY, KEY2, KEY3, ALFA))
        sys.stdout.close()
        escape = True
    elif io == "console":
        ALFA = alfa_choose()
        CIPHER = cipher_choose()
        KEY, KEY2, KEY3 = input_key(CIPHER, ALFA)
        TESTO = input_text(CIPHER, ALFA)
        

        print(csym(),"Ciphertext:")
        print(csym(),CIPYHER(CIPHER, TESTO, KEY, KEY2, KEY3, ALFA))
        print(csym())
        print(csym(),"Type \"exit\" to quit (anything else will restart the program):", end=" ")
        boom = input()
        if boom == "exit":
            escape = True
        print(csym())
    elif io == "surprise":
        bob = 0
    else:
        print(csym(),"Input not valid: txt or console")