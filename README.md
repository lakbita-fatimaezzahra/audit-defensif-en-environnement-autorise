# audit-defensif-en-environnement-autorise

MÉTHODOLOGIE DROZER

Étape 1: Installation du Drozer Agent (drozer-agent.apk) sur l'émulateur Android

<img width="1189" height="682" alt="Screenshot 2026-05-01 235546" src="https://github.com/user-attachments/assets/a5527057-14ab-45e8-a139-97540fd1c5a3" />

<img width="1338" height="378" alt="Screenshot 2026-05-02 155640" src="https://github.com/user-attachments/assets/83c368e0-9b85-4a50-ae28-95bb4404596e" />

Étape 2: Configuration du port forwarding TCP pour la connexion console

<img width="937" height="165" alt="Screenshot 2026-05-02 155751" src="https://github.com/user-attachments/assets/812cdf78-0613-4226-b2ab-7c13fd774c42" />

<img width="468" height="729" alt="Screenshot 2026-05-02 160911" src="https://github.com/user-attachments/assets/54d80a47-0af9-4dd9-9402-d881dbae64ab" />

Étape 3: Établissement d'une session Drozer interactive

<img width="1250" height="577" alt="Screenshot 2026-05-02 160020" src="https://github.com/user-attachments/assets/4fafc3a2-c3c1-4d58-babc-bb3215aa1017" />

ANALYSE DÉTAILLÉE DES RISQUES

RISQUE 1: Activities Exportées sans Protection

<img width="814" height="270" alt="image" src="https://github.com/user-attachments/assets/6aee688f-1636-45ad-baea-753646f16c3d" />

 *Activities Vulnérables Identifiées:*
 
MainActivity

Risque: CRITIQUE 

Impact: Accès à l'écran principal

APICredsActivity

Risque: CRITIQUE 

Impact: Exposition des identifiants API

APIcreds2Activity

Risque: CRITIQUE 

Impact: Exposition de données API supplémentaires

Exploitation Possible:

 Lancer MainActivity Intent intent = new Intent(); intent.setComponent(new
ComponentName( "jakhar.aseem.diva", "jakhar.aseem.diva.MainActivity" ));

startActivity(intent); # Avec Drozer dz> run app.activity.start \ --component
jakhar.aseem.diva \ jakhar.aseem.diva.APICredsActivity


*Vérification des Services et Receivers*

<img width="778" height="303" alt="image" src="https://github.com/user-attachments/assets/e9c4149d-2125-433f-9ae4-2e4989ab6a4c" />

 Analyse:
 
Services Exportés: Aucun détecté 

Broadcast Receivers Exportés: Aucun détecté 

Statut: Cette application réduit la surface d'attaque en n'exposant pas de services ou receivers

*Configuration du Content Provider*

<img width="913" height="343" alt="Screenshot 2026-05-02 161705" src="https://github.com/user-attachments/assets/0b510206-d992-4741-8458-ad5e0ea42a10" />

 Impact Critique:

■ Accès illimité en lecture à TOUTES les notes de l'application

■ Accès illimité en écriture pour modifier/supprimer les notes

■ Aucun mécanisme d'authentification ou d'autorisation

■ Données utilisateur exfiltrables par n'importe quelle application

■ Violation complète de la confidentialité des données

* ANALYSE DU MANIFEST*
  
  Début du AndroidManifest.xml
  
<img width="1201" height="833" alt="Screenshot 2026-05-02 162019" src="https://github.com/user-attachments/assets/5c844ac4-56f9-4807-9377-beb4589cc920" />

Déclaration des Activities

<img width="1080" height="851" alt="Screenshot 2026-05-02 162029" src="https://github.com/user-attachments/assets/6b0c6031-6a6b-4085-b8cd-23e3e9625dd8" />

 Problème Identifié:
 
Absence d'attribut 'exported': Sur les activities modernes, l'absence de

android:exported="false" combinée à un intent-filter rend l'activity accessible.

Activities vulnérables: • MainActivity - LAUNCHER (accessible au lancement) • LogActivity

- Logs de l'application • HardcodeActivity - Données en dur •

InsecureDataStorage1Activity • InsecureDataStorage2Activity •

InsecureDataStorage3Activity • InsecureDataStorage4Activity • SQLInjectionActivity •

InputValidation2URISchemeActivity • AccessControl1Activity • APICredsActivity Risque:

Chaque activity peut être lancée directement via intent explicite par une application tierce

* Détails des Intent Filters*

  <img width="950" height="742" alt="Screenshot 2026-05-02 162054" src="https://github.com/user-attachments/assets/fb53eb0f-1feb-4599-b650-29da0f0e4118" />

Analyse des Intent Filters:

MainActivity: Intent Filter: Actions: android.intent.action.MAIN Categories:

android.intent.category.LAUNCHER APICredsActivity: Intent Filter: Actions:

jakhar.aseem.diva.action.VIEW_CREDS Categories: android.intent.category.DEFAULT =>

Accessible via intent implicite APIcreds2Activity: Intent Filter: Actions:

jakhar.aseem.diva.action.VIEW_CREDS2 Categories: android.intent.category.DEFAULT =>

Accessible via intent implicite

*Découverte des Content Provider URIs*

<img width="1407" height="367" alt="Screenshot 2026-05-02 162326" src="https://github.com/user-attachments/assets/f510e171-7793-4b6d-b759-13c400f51a38" />

<img width="1043" height="261" alt="Screenshot 2026-05-02 162416" src="https://github.com/user-attachments/assets/c4c2b98b-7c25-496a-9a52-4a8257ba12e8" />

 URIs Accessibles Confirmées:

URI: content://jakhar.aseem.diva.provider.notesprovider/notes

Statut: Accessible

Données: TOUTES les notes

 PREUVES D'EXPLOITATION

 Exploitation du Content Provider
 
Lister les données via Content Provider dz> run app.provider.query \
content://jakhar.aseem.diva.provider.notesprovider/notes # Résultat: Extraction de toutes
les notes stockées # Modifier les données dz> run app.provider.update \
content://jakhar.aseem.diva.provider.notesprovider/notes \ --string title "Hacked" \
--string note "Your app is compromised" # Supprimer les données dz> run
app.provider.delete \ content://jakhar.aseem.diva.provider.notesprovider/notes
 Exploitation des Activities
 
 Lancer APICredsActivity directement Intent intent = new Intent();
intent.setComponent(new ComponentName( "jakhar.aseem.diva",
"jakhar.aseem.diva.APICredsActivity" )); startActivity(intent); # Result: Affichage de
toutes les données d'identification API # Avec Drozer dz> run app.activity.start \
--component jakhar.aseem.diva \ jakhar.aseem.diva.APICredsActivity

RECOMMANDATIONS DE SÉCURISATION

 Sécuriser le Content Provider

@Override public Cursor query(Uri uri, String[] projection, String selection, String[]

selectionArgs, String sortOrder) { // Vérifier la permission int perm =

checkCallingPermission( "com.jakhar.permission.READ_NOTES" ); if (perm !=

PackageManager.PERMISSION_GRANTED) { throw new SecurityException("Permission denied"); }

return super.query(uri, projection, selection, selectionArgs, sortOrder); }

 Sécuriser les Activities

@Override protected void onCreate(Bundle savedInstanceState) {

super.onCreate(savedInstanceState); // Vérifier l'authentification if

(!isUserAuthenticated()) { startActivity(new Intent(this, LoginActivity.class));

finish(); return; } // Vérifier les permissions if

(checkCallingPermission("com.example.VIEW_DATA") != PackageManager.PERMISSION_GRANTED) {

finish(); return; } setContentView(R.layout.main); }

 Meilleures Pratiques

■ Utiliser android:exported="false" par défaut

■ Implémenter une authentification forte

■ Utiliser des permissions personnalisées pour les composants sensibles

■ Valider tous les extras d'intent

■ Implémenter un contrôle d'accès granulaire

■ Chiffrer les données sensibles au repos et en transit

■ Tester régulièrement avec Drozer
■ Implémenter la journalisation et l'audit
