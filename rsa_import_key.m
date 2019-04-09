function rsa_import_key(filename_code)
if nargin<1,
   filename_code=[];
end;


dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

ini_file=[dirn,'\rsa_inifile.mat'];


workdir=pwd;
ini_rsa_import_key_FileDLGDir=workdir;  %<= default setting
if exist(ini_file,'file')~=2,
   save(ini_file,'ini_rsa_import_key_FileDLGDir');
else
   tmp=load(ini_file);
   if isfield(tmp,'ini_rsa_import_key_FileDLGDir'),
      ini_rsa_import_key_FileDLGDir=tmp.ini_rsa_import_key_FileDLGDir;
   end;
   clear tmp
end;
cd(ini_rsa_import_key_FileDLGDir);

if isempty(filename_code),
   mask='*.code';
   title_str='Load Key-File:';
   eval(['[filename_code, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(filename_code,0)| isequal(filename_code,0),
      return;
   end;
   filename_code=[pathname,filename_code];
end;
if isempty(filename_code),
   return;
end;



cd(workdir);
ini_rsa_import_key_FileDLGDir=pathname;
if strcmp(ini_rsa_import_key_FileDLGDir(end),filesep),
   ini_rsa_import_key_FileDLGDir=ini_rsa_import_key_FileDLGDir(1:end-1);
end;
save(ini_file,'ini_rsa_import_key_FileDLGDir','-append');




if exist(filename_code,'file')~=2,
   error('File %s does not exist!',filename_code);
end;

matfile=[dirn,'\key_identifiers.mat'];

%** retrieve the data from the key file

outfile_code=filename_code;

outf_decode=rsa_code(outfile_code,-1);
fid=fopen(outf_decode,'rt');
adr=fscanf(fid,'%s\n',1);
n=fscanf(fid,'%d\n',1);
e=fscanf(fid,'%d\n',1);
d=fscanf(fid,'%d\n',1);
fclose(fid);
delete(outf_decode);

if isempty(adr) || isempty(e),
   error('%s is not a valid key file!');
end;

if isempty(d),  %<= this is a public key
   is_priv_code=false;
   outfile_pub_code=[dirn,'\',adr,'.pub.code'];
else
   outfile_priv_code=[dirn,'\',adr,'.priv.code'];
   is_priv_code=true;
end;

%** check how to insert filenames in the key_identifier file: 
default_privID=[];
replace_default_privID=is_priv_code;
warn_for_PrivatKeyUpdate=is_priv_code;
if exist(matfile,'file')==2,
   keyID=[];
   default_privID=[];
   load(matfile,'keyID','default_privID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},adr),
         i=k;
         break;
      end;
   end;
   if i>0,
      if ~isempty(keyID{i,3}) && ~is_priv_code,
         warning('rsa_import_key:PubOnPrivError','Can''t import public key on existent private key!');
         return;
      end;
      resp=questdlg(sprintf('%s found in key_identifier file! Do you want to overwrite the content?',adr),' ','Yes','No','No');
      if isempty(resp) || strcmp(resp,'No');
         return;
      end;
      if is_priv_code && ~strcmp(adr,default_privID) && ~isempty(default_privID),
         resp=questdlg(sprintf('Your present default private key is %s. Do you want to change it to %s ?',default_privID,adr),' ','Yes','No','No');
         replace_default_privID=(~isempty(resp) && ~strcmp(resp,'No'));
      end;
      if is_priv_code && strcmp(adr,default_privID),
         replace_default_privID=false;
      end;
      
      
      if ~isempty(keyID{i,3}) && is_priv_code,
         outfile_code=[dirn,filesep,keyID{i,3}];
         outf_decode=rsa_code(outfile_code,-1);
         fid=fopen(outf_decode,'rt');
         adr=fscanf(fid,'%s\n',1);
         n_1=fscanf(fid,'%d\n',1);
         e_1=fscanf(fid,'%d\n',1);
         d_1=fscanf(fid,'%d\n',1);
         fclose(fid);
         delete(outf_decode);
         warn_for_PrivatKeyUpdate=(n~=n_1 || e~=e_1);
      end;
            
      
      
   end;
end;

if is_priv_code,
   %** create the public key file: ***
   outfile=[dirn,'\',adr,'.pub'];
   fid=fopen(outfile,'wt');
   fprintf(fid,'%s\n',adr);
   fprintf(fid,'%d\n%d\n',n,e);
   fclose(fid);
   
   outfile_pub_code=rsa_code(outfile,1);
   delete(outfile);
else
   outfile_priv_code=[];
end;

if is_priv_code,
   copied_filename=outfile_priv_code;
else
   copied_filename=outfile_pub_code;
end;
if ~strcmp(filename_code,copied_filename)
   copyfile(filename_code,copied_filename);
   [fp,fn,fe]=fileparts(filename_code);
   filename_code_no_path=[fn,fe];
   [fp,fn,fe]=fileparts(copied_filename);
   copied_filename=[fn,fe];
   
   resp=questdlg(sprintf('original %s is copied to %s in your the private database. Do you want to delete the original? (recommended)',filename_code_no_path,copied_filename),' ','Yes','No','Yes');
   if isempty(resp) || strcmp(resp,'Yes');
      delete(filename_code);
   end;
end;

if ~isempty(outfile_priv_code),
   [fp,fn,fe]=fileparts(outfile_priv_code);
   outfile_priv_code=[fn,fe];
end;
[fp,fn,fe]=fileparts(outfile_pub_code);
outfile_pub_code=[fn,fe];



%*** update the key_identifier file: ***
if exist(matfile,'file')~=2,
   keyID={adr,outfile_pub_code,outfile_priv_code};
else
   keyID=[];
   default_privID=[];
   load(matfile,'keyID','default_privID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},adr),
         i=k;
         break;
      end;
   end;
   if i<0,
      i=size(keyID,1)+1;
   end;
   keyID{i,1}=adr;
   keyID{i,2}=outfile_pub_code;
   keyID{i,3}=outfile_priv_code;
end;
if replace_default_privID,
   if isempty(default_privID),
      warndlg(sprintf('Default privat key has been set to %s',adr),'!! Info !!')
   else
      warndlg(sprintf('Old default privat key %s has been modified to %s',default_privID,adr),'!! Info !!')
   end;
   default_privID=adr;
end;
if warn_for_PrivatKeyUpdate,
   warndlg(sprintf('Privat key has been modified. Consider dending %s to all who want to send mails to %s!',outfile_pub_code,adr),'!! Info !!')
end;
save(matfile,'keyID','default_privID');

end
