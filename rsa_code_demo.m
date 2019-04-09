basedir={'c:\users\eggert\txt','d:\users\eggert\txt'};
basedir=get_first_existent_directory(basedir);
fn='e_mail_signature.txt';
filename=[basedir,filesep,fn];

%% encoding and decoding with default keys:
outn1=rsa_code(filename,1);
outn2=rsa_code(outn1,-1);
dos(['fc /B ',filename,' ',outn2]);
delete(outn1);
delete(outn2);

%% ** encoding with public key, decoding with private key  (thats the normal way of operation!!)
n=3321011; e=1660505; d=1402937;
outn1=rsa_code(filename,n,e,'encode');
outn2=rsa_code(outn1,n,d,'decode');
dos(['fc /B ',filename,' ',outn2]);
delete(outn1);
delete(outn2);

%% ** encoding with private key, decoding with public key
n=3561491; e=1780745; d=2313737;
outn1=rsa_code(filename,n,d,'encode');
outn2=rsa_code(outn1,n,e,'decode');
dos(['fc /B ',filename,' ',outn2]);
delete(outn1);
delete(outn2);

%% ** generate and check signature with default keys 
%outn1=rsa_generate_signature([],[],[],NaN); % format without date (this signature never expires)
%outn1=rsa_generate_signature([]); % format with date (this signature expires 5 days after today)
outn1=rsa_generate_signature([],[],[],'12.10.2015'); % format with date (this signature expires 5 days after the 12.10.2015)
% owner of the public key can check the signature
fprintf('rsa_check_signature=%d\n',rsa_check_signature(outn1,[]));
delete(outn1);
%% ** use special keys rather than the default keys:
%**** generate and check signature without date encoding 
n=3321011; e=1660505; d=1402937;
%outn1=rsa_generate_signature(n,d,e,NaN); % format without date (this signature never expires)
%outn1=rsa_generate_signature(n,d,e); % format with date (this signature expires 5 days after today)
outn1=rsa_generate_signature(n,d,e,'12.10.2015'); % format with date (this signature expires 5 days after the 12.10.2015)
ws=warning('off','rsa_check_signature:OutOfDate');
fprintf('rsa_check_signature=%d\n',rsa_check_signature(outn1,n,e));
warning(ws);
delete(outn1);
%% *** decode without writing to disk: **************
n=3561491; e=1780745; d=2313737;
outn1=rsa_code(filename,n,e,'encode');
x=rsa_code(outn1,n,d,'decode','return')
delete(outn1);

