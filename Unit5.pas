unit Unit5;

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Serializer.Commons,
  System.Classes,
  Web.HTTPApp,
  MVCFramework.Middleware.Swagger,
  MVCFramework.Middleware.StaticFiles,
  System.SysUtils,
  MVCFramework.Swagger.Commons,
  MVCFramework.Logger,
  System.Generics.Collections,
  System.StrUtils,
  Xml.XMLDoc,
  Xml.omnixmldom,
  Vcl.Dialogs,
  IdHTTP,
  IdMultipartFormData,
  IdSSLOpenSSL,
  MSXML,
  ComObj,
  System.IOUtils,
  MVCFramework.JWT,
  System.NetEncoding,
  System.JSON,
  SHDocVw,
  ActiveX,
  xmldom,
  XMLIntf,
  msxmldom,
  ShellAPI,

  // uses de la dll----------------------
  Crypt2, Global,
  Http, StringBuilder, PrivateKey,
  XmlDSigGen, Cert, Xml, XmlDSig,
  HttpResponse, Rest, JsonObject,
  HttpRequest, Stream, BinData,
  // ------------------------------------

  // Jose JWT------------------------------
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON, Vcl.Mask;
// -------------------------------------

type

  [MVCPath('/fe')]
  TMyController = class(TMVCController)

    // Parte del JWT--------------------------------
  private const
    SECRET_CAPTION = 'Secret (%dbit)';
    // --------------------------------------------

  private
    FToken: string;

    function VerifyTokenComplete: Boolean;
    function VerifyToken: Boolean;
    function BuildToken: string;
    function GenerateToken: string;
    function VerificarArchivoCorrecto(xmlFile: string): Boolean;
    function GenerateResponseXML: string;
    function ActivarLicencia(): Boolean;
    function FirmarAcuseRecibo(vXMLFirmado: String): Boolean;
    function VerificarFirma(vXMLFirmado: String): Boolean;
    function FirmarAprobaciónComercial(vXMLFirmado: String): Boolean;

  public

    [MVCHTTPMethod([httpPOST])]
    [MVCPath('/ecf/($Token)')]
    [MVCSwagSummary('Verificar Token', '', '1')]
    procedure AuthenticateToken(var Token: string);

    [MVCPath('/Autenticacion/api/Semilla')]
    [MVCSwagSummary('Autenticacion', '', '1')]
    [MVCHTTPMethod([httpGET])]
    procedure UploadFile;

    [MVCHTTPMethod([httpPOST])]
    [MVCPath('/Autenticacion/api/ValidacionCertificado')]
    [MVCSwagSummary('Autenticacion', '', '2')]
    [MVCSwagParam(plBody, 'XML', '', ptString, true)]
    procedure Autenticacion;

    [MVCHTTPMethod([httpPOST])]
    [MVCPath('/AprobacionComercial/api/ecf')]
    [MVCSwagSummary('Recepcion', '', '1')]
    [MVCSwagParam(plBody, 'XML', '', ptString, true)]
    procedure AprobacionComercial;

    [MVCHTTPMethod([httpPOST])]
    [MVCPath('/Recepcion/api/ecf')]
    [MVCSwagSummary('Recepcion', '', '2')]
    [MVCSwagParam(plBody, 'XML', '', ptString, true)]
    procedure Recepcion;

    procedure Auditar(mensaje: string);

  protected
    procedure OnBeforeAction(Context: TWebContext; const AActionName: string;
      var Handled: Boolean); override;
  end;

var
  TokenVerified: Boolean;
  TokenVerificationTime: TDateTime;
  value: file;
  Xml: String;
  XMLsign: String;
  FCompact: string;
  edtSecret: string;
  cbbAlgorithm: integer;

implementation

uses
  MVCFramework.Serializer.Defaults,
  System.DateUtils, System.Net.HttpClient,
  Winapi.Windows,
  Winapi.Messages,
  System.Win.Registry,
  System.Net.Mime,
  JOSE.Core.Builder;

function TMyController.VerifyTokenComplete: Boolean;
var
  LKey: TJWK;
  LToken: TJWT;
  LSigner: TJWS;
begin
  LKey := TJWK.Create(edtSecret);
  try
    LToken := TJWT.Create;
    try
      LSigner := TJWS.Create(LToken);
      try
        LSigner.SetKey(LKey);
        LSigner.CompactToken := FCompact;
        Result := LSigner.VerifySignature;
      finally
        LSigner.Free;
      end;
    finally
      LToken.Free;
    end;
  finally
    LKey.Free;
  end;
end;

function TMyController.VerifyToken: Boolean;
var
  LToken: TJWT;
begin
  Result := False;

  // Unpack and verify the token
  LToken := TJOSE.Verify(edtSecret, FCompact);

  if Assigned(LToken) then
  begin
    try
      Result := LToken.Verified;
    finally
      LToken.Free;
    end;
  end;
end;

function TMyController.BuildToken: string;
var
  LToken: TJWT;
  LAlg: TJOSEAlgorithmId;
begin
  // Create a JWT Object
  LToken := TJWT.Create;
  try
    // Token claims

    LToken.Claims.Subject := 'Jhoneymi Batista Mena';
    LToken.Claims.JWTId := '79e4e239-21b0-4ce4-8bd5-1ded74f7a50e';
    LToken.Claims.NotBefore := Now;
    LToken.Claims.Expiration := Now + 1;
    LToken.Claims.Issuer := 'Jamensof';
    LToken.Claims.Audience := 'Jamensoft.User';

    // Signing algorithm
    case cbbAlgorithm of
      0:
        LAlg := TJOSEAlgorithmId.HS256;
      1:
        LAlg := TJOSEAlgorithmId.HS384;
      2:
        LAlg := TJOSEAlgorithmId.HS512;
    else
      LAlg := TJOSEAlgorithmId.HS256;
    end;

    // Signing and compact format creation.
    FCompact := TJOSE.SerializeCompact(edtSecret, LAlg, LToken);

    // Token in compact representation
    Xml := FCompact;

    // Header and Claims JSON representation
    Auditar('Header: ' + TJSONUtils.ToJSON(LToken.Header.JSON));
    Auditar('Claims: ' + TJSONUtils.ToJSON(LToken.Claims.JSON));
  finally
    LToken.Free;
  end;
end;

function TMyController.VerificarFirma(vXMLFirmado: String): Boolean;
var
  dsig: HCkXmlDSig;
  success: Boolean;
  numSignatures: integer;
  i: integer;
  bVerifyRefDigests: Boolean;
  bSignatureVerified: Boolean;
  numRefDigests: integer;
  j: integer;
  bDigestVerified: Boolean;

begin
  Try
    ActivarLicencia();
    Result := False;

    dsig := CkXmlDSig_Create();
    success := CkXmlDSig_LoadSignature(dsig, PWChar(vXMLFirmado));

    numSignatures := CkXmlDSig_getNumSignatures(dsig);
    i := 0;
    while i < numSignatures do
    begin
      CkXmlDSig_putSelector(dsig, i);

      bVerifyRefDigests := False;
      bSignatureVerified := CkXmlDSig_VerifySignature(dsig, bVerifyRefDigests);
      if (bSignatureVerified = true) then
      begin
        Auditar('Firma Verificada ' + IntToStr(i + 1));
        Result := true;
      end
      else
      begin
        Auditar('Firma Invalida ' + IntToStr(i + 1));
      end;

      // Check each of the reference digests separately..
      numRefDigests := CkXmlDSig_getNumReferences(dsig);
      j := 0;
      while j < numRefDigests do
      begin
        bDigestVerified := CkXmlDSig_VerifyReferenceDigest(dsig, j);
        Auditar('reference digest ' + IntToStr(j + 1) + ' verified = ' +
          IntToStr(Ord(bDigestVerified)));
        if (bDigestVerified = False) then
        begin
          Auditar('Error al verificar, razon: ' +
            IntToStr(CkXmlDSig_getRefFailReason(dsig)));
        end;
        j := j + 1;
      end;

      i := i + 1;
    end;

    CkXmlDSig_Dispose(dsig);
  Except
    on e: Exception do
    begin
      Result := False;
      Auditar('Error al Validar Firma. Error: ' + e.Message);
    end;
  End;
end;

function TMyController.FirmarAcuseRecibo(vXMLFirmado: String): Boolean;
var
  success: Boolean;
  xmlToSign: HCkXml;
  gen: HCkXmlDSigGen;
  Cert: HCkCert;
  sbXml: HCkStringBuilder;
  verifier: HCkXmlDSig;
  numSigs: integer;
  verifyIdx: integer;
  Verified: Boolean;
  RNCEmisor: string;
  RNCComprador: string;
  eNCF: PWideChar;
  dsig: HCkXmlDSig;

  Xml: HCkXml;
  veNCF: PWideChar;
  vRNCEmisor, vRNCComprador: integer;
begin
  Try
    Try

      ActivarLicencia();

      // Primero Cargamos el XML con los datos ya
      Xml := CkXml_Create();

      success := CkXml_LoadXml(Xml, PWChar(vXMLFirmado));
      if (success <> true) then
      begin
        Auditar('Error al cargar XML Recibido. Error: ' +
          CkXml__lastErrorText(Xml));
        Result := False;
        Exit;
      end;

      vRNCEmisor := CkXml_GetChildIntValue(Xml, 'Encabezado|Emisor|RNCEmisor');
      vRNCComprador := CkXml_GetChildIntValue(Xml,
        'Encabezado|Comprador|RNCComprador');
      veNCF := CkXml__getChildContent(Xml, 'Encabezado|IdDoc|eNCF');

      success := true;
      // Creamos el ACUSE Recibo, para luego firmar el mismo.
      xmlToSign := CkXml_Create();
      CkXml_putTag(xmlToSign, 'ARECF');
      CkXml_AddAttribute(xmlToSign, 'xmlns:xsi',
        'http://www.w3.org/2001/XMLSchema-instance');
      CkXml_AddAttribute(xmlToSign, 'xmlns:xsd',
        'http://www.w3.org/2001/XMLSchema');
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAcusedeRecibo|Version', '1.0');
      CkXml_UpdateChildContent(xmlToSign, 'DetalleAcusedeRecibo|RNCEmisor',
        PWChar(IntToStr(vRNCEmisor)));
      CkXml_UpdateChildContent(xmlToSign, 'DetalleAcusedeRecibo|RNCComprador',
        PWChar(IntToStr(vRNCComprador)));
      CkXml_UpdateChildContent(xmlToSign, 'DetalleAcusedeRecibo|eNCF', veNCF);
      CkXml_UpdateChildContent(xmlToSign, 'DetalleAcusedeRecibo|Estado', '0');
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAcusedeRecibo|FechaHoraAcuseRecibo',
        PWChar(FormatDateTime('dd-mm-yyyy hh:mm:ss', Now)));

      gen := CkXmlDSigGen_Create();

      CkXmlDSigGen_putSigLocation(gen, 'ARECF');
      CkXmlDSigGen_putSigLocationMod(gen, 0);
      CkXmlDSigGen_putSigNamespacePrefix(gen, '');
      CkXmlDSigGen_putSigNamespaceUri(gen,
        'http://www.w3.org/2000/09/xmldsig#');
      CkXmlDSigGen_putSignedInfoCanonAlg(gen, 'C14N');
      CkXmlDSigGen_putSignedInfoDigestMethod(gen, 'sha256');

      // -------- Reference 1 --------
      CkXmlDSigGen_AddSameDocRef(gen, '', 'sha256', '', '', '');

      // Certificado Digital y su Clave
      Cert := CkCert_Create();
      success := CkCert_LoadPfxFile(Cert,
        'C:\Users\soporte\Downloads\Jamensoft-API\4300935_identity.p12',
        '@merican21.');
      if (success <> true) then
      begin
        Auditar(CkCert__lastErrorText(Cert));
        Result := False;
        Exit;
      end;
      CkXmlDSigGen_SetX509Cert(gen, Cert, true);

      CkXmlDSigGen_putKeyInfoType(gen, 'X509Data');
      CkXmlDSigGen_putX509Type(gen, 'Certificate');

      // Load XML to be signed...
      sbXml := CkStringBuilder_Create();
      CkXml_GetXmlSb(xmlToSign, sbXml);

      CkXmlDSigGen_putBehaviors(gen, 'CompactSignedXml');

      // Firma el XML
      success := CkXmlDSigGen_CreateXmlDSigSb(gen, sbXml);
      if (success <> true) then
      begin
        Auditar(CkXmlDSigGen__lastErrorText(gen));
        Result := False;
        Exit;
      end;
      // -----------------------------------------------

      // Guardar el Acuse luego de firmado.
      success := CkStringBuilder_WriteFile(sbXml,
        PWChar('C:\NemeSys\' + IntToStr(vRNCComprador) + veNCF + '.xml'),
        'utf-8', False);
      Auditar(CkStringBuilder__getAsString(sbXml));

      // ----------------------------------------
      // Verifica si la firma se colocaron correctamente.
      verifier := CkXmlDSig_Create();
      success := CkXmlDSig_LoadSignatureSb(verifier, sbXml);
      if (success <> true) then
      begin
        Auditar(CkXmlDSig__lastErrorText(verifier));
        Result := False;
        Exit;
      end;

      numSigs := CkXmlDSig_getNumSignatures(verifier);
      verifyIdx := 0;
      while verifyIdx < numSigs do
      begin
        CkXmlDSig_putSelector(verifier, verifyIdx);
        Verified := CkXmlDSig_VerifySignature(verifier, true);
        if (Verified <> true) then
        begin
          Auditar(CkXmlDSig__lastErrorText(verifier));
          Result := False;
          Exit;
        end;
        verifyIdx := verifyIdx + 1;
      end;

      // Respuesta del XML Creado para enviar al RENDER;
      XMLsign := CkStringBuilder__getAsString(sbXml);
      Auditar('Archivo Firmado Satisfactoriamente!');
      Result := true;

    Finally
      CkXml_Dispose(xmlToSign);
      CkXmlDSigGen_Dispose(gen);
      CkCert_Dispose(Cert);
      CkStringBuilder_Dispose(sbXml);
      CkXmlDSig_Dispose(verifier);
      CkXmlDSig_Dispose(Xml);
    End;

  Except
    on e: Exception do
    begin
      Result := False;
      Auditar('---Firmando Semilla: Error al Firmar Archivo. Error: ' +
        e.Message);
      MessageDlg('Firmando Semilla: Error al Firmar Archivo. Error: ' +
        e.Message, mtError, [mbOk], 0);
    end;
  End;
end;

function TMyController.FirmarAprobaciónComercial(vXMLFirmado: String): Boolean;
var
  success: Boolean;
  xmlToSign: HCkXml;
  gen: HCkXmlDSigGen;
  Cert: HCkCert;
  sbXml: HCkStringBuilder;
  verifier: HCkXmlDSig;
  numSigs: integer;
  verifyIdx: integer;
  Verified: Boolean;
  RNCEmisor: string;
  RNCComprador: string;
  eNCF: PWideChar;
  dsig: HCkXmlDSig;

  Xml: HCkXml;
  veNCF: PWideChar;
  vRNCEmisor, vMontoTotal, vRNCComprador: integer;
begin
  Try
    Try

      ActivarLicencia();

      // Primero Cargamos el XML con los datos ya
      Xml := CkXml_Create();

      success := CkXml_LoadXml(Xml, PWChar(vXMLFirmado));
      if (success <> true) then
      begin
        Auditar('Error al cargar XML Recibido. Error: ' +
          CkXml__lastErrorText(Xml));
        Result := False;
        Exit;
      end;

      vMontoTotal := CkXml_GetChildIntValue(Xml,
        'Encabezado|Totales|MontoTotal');
      vRNCEmisor := CkXml_GetChildIntValue(Xml, 'Encabezado|Emisor|RNCEmisor');
      vRNCComprador := CkXml_GetChildIntValue(Xml,
        'Encabezado|Comprador|RNCComprador');
      veNCF := CkXml__getChildContent(Xml, 'Encabezado|IdDoc|eNCF');

      success := true;
      // Creamos el ACUSE Recibo, para luego firmar el mismo.
      xmlToSign := CkXml_Create();
      CkXml_putTag(xmlToSign, 'ACECF');
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|Version', '1.0');
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|RNCEmisor', PWChar(IntToStr(vRNCEmisor)));
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|eNCF', veNCF);
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|FechaEmision',
        PWChar(FormatDateTime('dd-mm-yyyy', Now)));
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|MontoTotal', PWChar(IntToStr(vMontoTotal)));
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|RNCComprador',
        PWChar(IntToStr(vRNCComprador)));
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|Estado', '1');
      CkXml_UpdateChildContent(xmlToSign,
        'DetalleAprobacionComercial|FechaHoraAprobacionComercial',
        PWChar(FormatDateTime('dd-mm-yyyy hh:mm:ss', Now)));

      gen := CkXmlDSigGen_Create();

      CkXmlDSigGen_putSigLocation(gen, 'ACECF');
      CkXmlDSigGen_putSigLocationMod(gen, 0);
      CkXmlDSigGen_putSigNamespacePrefix(gen, '');
      CkXmlDSigGen_putSigNamespaceUri(gen,
        'http://www.w3.org/2000/09/xmldsig#');
      CkXmlDSigGen_putSignedInfoCanonAlg(gen, 'C14N');
      CkXmlDSigGen_putSignedInfoDigestMethod(gen, 'sha256');

      // -------- Reference 1 --------
      CkXmlDSigGen_AddSameDocRef(gen, '', 'sha256', '', '', '');

      // Certificado Digital y su Clave
      Cert := CkCert_Create();
      success := CkCert_LoadPfxFile(Cert,
        'C:\Users\soporte\Downloads\Jamensoft-API\4300935_identity.p12',
        '@merican21.');
      if (success <> true) then
      begin
        Auditar(CkCert__lastErrorText(Cert));
        Result := False;
        Exit;
      end;
      CkXmlDSigGen_SetX509Cert(gen, Cert, true);

      CkXmlDSigGen_putKeyInfoType(gen, 'X509Data');
      CkXmlDSigGen_putX509Type(gen, 'Certificate');

      // Load XML to be signed...
      sbXml := CkStringBuilder_Create();
      CkXml_GetXmlSb(xmlToSign, sbXml);

      CkXmlDSigGen_putBehaviors(gen, 'CompactSignedXml');

      // Firma el XML
      success := CkXmlDSigGen_CreateXmlDSigSb(gen, sbXml);
      if (success <> true) then
      begin
        Auditar(CkXmlDSigGen__lastErrorText(gen));
        Result := False;
        Exit;
      end;
      // -----------------------------------------------

      // Guardar el Acuse luego de firmado.
      success := CkStringBuilder_WriteFile(sbXml,
        PWChar('C:\NemeSys\' + IntToStr(vRNCComprador) + veNCF + '.xml'),
        'utf-8', False);

      Auditar(CkStringBuilder__getAsString(sbXml));

      // ----------------------------------------
      // Verifica si la firma se colocaron correctamente.
      verifier := CkXmlDSig_Create();
      success := CkXmlDSig_LoadSignatureSb(verifier, sbXml);
      if (success <> true) then
      begin
        Auditar(CkXmlDSig__lastErrorText(verifier));
        Result := False;
        Exit;
      end;

      numSigs := CkXmlDSig_getNumSignatures(verifier);
      verifyIdx := 0;
      while verifyIdx < numSigs do
      begin
        CkXmlDSig_putSelector(verifier, verifyIdx);
        Verified := CkXmlDSig_VerifySignature(verifier, true);
        if (Verified <> true) then
        begin
          Auditar(CkXmlDSig__lastErrorText(verifier));
          Result := False;
          Exit;
        end;
        verifyIdx := verifyIdx + 1;
      end;

      // Respuesta del XML Creado para enviar al RENDER;
      XMLsign := CkStringBuilder__getAsString(sbXml);
      Auditar('Archivo Firmado Satisfactoriamente!');
      Result := true;

    Finally
      CkXml_Dispose(xmlToSign);
      CkXmlDSigGen_Dispose(gen);
      CkCert_Dispose(Cert);
      CkStringBuilder_Dispose(sbXml);
      CkXmlDSig_Dispose(verifier);
      CkXmlDSig_Dispose(Xml);
    End;

  Except
    on e: Exception do
    begin
      Result := False;
      Auditar('---Firmando Semilla: Error al Firmar Archivo. Error: ' +
        e.Message);
      MessageDlg('Firmando Semilla: Error al Firmar Archivo. Error: ' +
        e.Message, mtError, [mbOk], 0);
    end;
  End;
end;

function TMyController.ActivarLicencia(): Boolean;
var
  glob: HCkGlobal;
  success: Boolean;
  status: integer;
  xSerial: PWChar;
begin
  // xSerial :=  PWChar(Serial);
  xSerial := 'oEZL9n.CBX0228_ULmpKlXO2D0T';
  glob := CkGlobal_Create();
  success := CkGlobal_UnlockBundle(glob, xSerial);
  Auditar('---Activando Licencia DLL XML: Activando....');

  if (success <> true) then
  begin
    Auditar('---Activando Licencia DLL XML: ' + CkGlobal__lastErrorText(glob));
    Exit;
  end;

  status := CkGlobal_getUnlockStatus(glob);
  if (status = 2) then
    Auditar('---Activando Licencia DLL XML: Desbloqueado Satisfactoriamente!')
  else
  begin
    Auditar('---Activando Licencia DLL XML: Modo Prueba... Verifique');
    Auditar('---Activando Licencia DLL XML: ' + CkGlobal__lastErrorText(glob));
  end;

  CkGlobal_Dispose(glob);

  Result := success;
end;

function GenerateToken: string;
var
  Guid: TGuid;
  TokenBytes: TBytes;
begin
  CreateGUID(Guid);
  TokenBytes := TEncoding.UTF8.GetBytes(GUIDToString(Guid));
  Result := TNetEncoding.Base64.EncodeBytesToString(TokenBytes);
end;

function TMyController.GenerateToken: string;
var
  Guid: TGuid;
  GuidStr: string;
  i: integer;
begin
  CreateGUID(Guid);
  GuidStr := GUIDToString(Guid);

  // Eliminar las llaves del GUID
  GuidStr := StringReplace(GuidStr, '{', '', [rfReplaceAll]);
  GuidStr := StringReplace(GuidStr, '}', '', [rfReplaceAll]);

  // Reemplazar los caracteres no alfanuméricos por caracteres alfanuméricos
  for i := 1 to Length(GuidStr) do
  begin
    case GuidStr[i] of
      '0':
        GuidStr[i] := 'A';
      '1':
        GuidStr[i] := '0';
      '2':
        GuidStr[i] := '7';
      '3':
        GuidStr[i] := '3';
      '4':
        GuidStr[i] := 'E';
      '5':
        GuidStr[i] := '4';
      '6':
        GuidStr[i] := 'G';
      '7':
        GuidStr[i] := '1';
      '8':
        GuidStr[i] := 'I';
      '9':
        GuidStr[i] := '9';
      'A' .. 'Z':
        GuidStr[i] := Char(Ord(GuidStr[i]) + 32); // Convertir a minúscula
      'a' .. 'z':
        GuidStr[i] := Char(Ord(GuidStr[i]) - 32); // Convertir a mayúscula
    else
      GuidStr[i] := 'K';
      // Caracter por defecto para caracteres no alfanuméricos
    end;
  end;

  // Agregar caracteres especiales
  GuidStr := GuidStr + GuidStr + GuidStr + GuidStr + '==';

  Result := GuidStr;
end;

function TMyController.VerificarArchivoCorrecto(xmlFile: string): Boolean;
var
  XMLDoc: IXMLDocument;
  RootNode: IXMLNode;
  Node: IXMLNode;
begin
  Result := False;

  XMLDoc := TXMLDocument.Create(nil);
  try
    XMLDoc.LoadFromFile(xmlFile);
    XMLDoc.Active := true;

    RootNode := XMLDoc.DocumentElement;
    if Assigned(RootNode) then
    begin
      Node := RootNode.ChildNodes.FindNode('SemillaModel');
      Node := RootNode.ChildNodes.FindNode('SemillaModel|valor');
      if Assigned(Node) then
      begin
        // El nodo <SemillaModel> existe en el archivo XML
        Result := true;
      end;
    end;
  finally
    XMLDoc.Active := False;
    XMLDoc := nil;
  end;
end;

function TMyController.GenerateResponseXML: string;
begin
  Result := '<?xml version="1.0" encoding="UTF-8"?>' + sLineBreak +
    '<RespuestaAutenticacion>' + sLineBreak + '  <token>' + GenerateToken +
    '</token>' + sLineBreak + '  <expira>' +
    FormatDateTime('yyyy-mm-dd"T"hh:nn:ss.zzz"Z"', Now) + '</expira>' +
    sLineBreak + '  <expedido>' + FormatDateTime('yyyy-mm-dd"T"hh:nn:ss.zzz"Z"',
    Now) + '</expedido>' + sLineBreak + '</RespuestaAutenticacion>';
end;

procedure TMyController.Auditar(mensaje: string);
var
  F: TextFile;
  Filename: String;
  Mutex: THandle;
  SearchRec: TSearchRec;
begin
  // Insertamos la fecha y la hora
  mensaje := FormatDateTime('[ddd dd mmm yyyy, hh:mm:ss:nn] ', Now) + mensaje;
  // El nombre del archivo es igual al del ejecutable, pero con la extension .log
  Filename := ChangeFileExt(ParamStr(0), '.log');
  // Creamos un mutex, usando como identificador unico la ruta completa del ejecutable
  Mutex := CreateMutex(nil, False, PChar(StringReplace(ParamStr(0), '\', '/',
    [rfReplaceAll])));
  if Mutex <> 0 then
  begin
    // Esperamos nuestro turno para escribir
    WaitForSingleObject(Mutex, INFINITE);
    try
      // Comprobamos el tamaño del archivo
      if FindFirst(Filename, faAnyFile, SearchRec) = 0 then
      begin
        // // Si es mayor de un mega lo copiamos a (nombre).log.1
        // if SearchRec.Size > (1024*1024) then
        // MoveFileEx(PChar(Filename),PChar(Filename + '.1'),
        // MOVEFILE_REPLACE_EXISTING);
        // FindClose(SearchRec);
      end;
      try
        AssignFile(F, Filename);
{$I-}
        Append(F);
        if IOResult <> 0 then
          Rewrite(F);
{$I+}
        if IOResult = 0 then
        begin
          // Escribimos el mensaje
          Writeln(F, mensaje);
          CloseFile(F);
        end;
      except
        //
      end;
    finally
      ReleaseMutex(Mutex);
      CloseHandle(Mutex);
    end;
  end;
end;

procedure TMyController.OnBeforeAction(Context: TWebContext;
  const AActionName: string; var Handled: Boolean);
begin
  { Executed before each action
    if handled is true (or an exception is raised) the actual
    action will not be called }
  inherited;
end;

procedure TMyController.UploadFile;
var
  Token: string;
  XMLContent: string;
begin
  Try
    Auditar('Cargando Semilla.');
    Context.Response.SetCustomHeader('Access-Control-Allow-Origin', '*');

    // Generar el token para el usuario
    Token := GenerateToken();

    // Crear la representación XML del token
    XMLContent := '<?xml version="1.0" encoding="utf-8"?>' + sLineBreak +
      '<SemillaModel xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
      + sLineBreak + '  <valor>' + Token + '</valor>' + sLineBreak + '  <fecha>'
      + FormatDateTime('YYYY-MM-DD"T"hh:mm:ss.sssssZ"-04:00"', Now) + '</fecha>'
      + sLineBreak + '</SemillaModel>';

    // 2023-07-14T11:07:12.822141-04:00

    // Establecer la respuesta HTTP con el contenido XML, el tipo de medios y la codificación adecuados
    Context.Response.ContentType := 'application/xml; charset=utf-8';
    Context.Response.Content := XMLContent;

    Auditar('Cargando Semilla:' + XMLContent);
    Auditar('Cargando Semilla: Satisfactoriamente!');

  Except
    on e: Exception do
    begin
      Auditar('Cargando Semilla: Error: ' + e.Message);
    end;
  End;
end;

procedure TMyController.Autenticacion;
var
  XMLDoc: IXMLDocument;
  XMLText: string;
  TokenExpiration: TDateTime;
begin

  Context.Response.SetCustomHeader('Access-Control-Allow-Origin', '*');

//  // Validar la estructura del testo
//  if VerificarArchivoCorrecto(Context.Request.Body) then
//  begin
//    Render(400, 'La Estructura del xml no es Correcta');
//  end;

  // Validar el archivo XML
  if not VerificarFirma(Context.Request.Body) then
  begin
    // En caso de que el archivo XML no esté firmado correctamente
    Render(400, 'El archivo XML no está firmado correctamente.');
    Exit;
  end;

  // Generar el token
  var
    Token: string := BuildToken;

    // Crear la estructura de respuesta JSON
  var
    JSONResponse: TJSONObject := TJSONObject.Create;
  JSONResponse.AddPair('Token', Xml);
  JSONResponse.AddPair('expira', DateTimeToStr(Now + EncodeTime(1, 0, 0, 0)));
  // Agregar 1 hora a la hora actual
  JSONResponse.AddPair('expedido', DateTimeToStr(Now));

  // Devolver la respuesta al cliente
  Render(200, JSONResponse.ToString);

end;

procedure TMyController.AprobacionComercial;
var
  TimeDiff: TDateTime;
  XMLDoc: IXMLDocument;
  XMLText: string;
  TokenExpiration: TDateTime;

begin

  // Verificar si el token ha sido verificado y si ha pasado menos de 1 hora desde la verificación
  if TokenVerified then
  begin
    TimeDiff := Now - TokenVerificationTime;
    // Verificar si ha pasado menos de 1 hora desde la verificación del token
    if TimeDiff <= EncodeTime(1, 0, 0, 0) then
    begin

      if FirmarAprobaciónComercial(Context.Request.Body) then
      begin
        Context.Response.ContentType := 'application/xml; charset=utf-8';
        Context.Response.Content := XMLsign;
      end
      else
        Render('HTTP 400');

    end;
  end
  else
    Render('No se ha verificado el token o ha expirado.');
end;

procedure TMyController.Recepcion;
var
  TimeDiff: TDateTime;
  XMLDoc: IXMLDocument;
  XMLText: string;
  TokenExpiration: TDateTime;
  RNCEmisor, RNCComprador, eNCF: string;

begin

  Context.Response.SetCustomHeader('Access-Control-Allow-Origin', '*');

  // Verificar si el token ha sido verificado y si ha pasado menos de 1 hora desde la verificación
  if TokenVerified then
  begin
    TimeDiff := Now - TokenVerificationTime;
    // Verificar si ha pasado menos de 1 hora desde la verificación del token
    if TimeDiff <= EncodeTime(1, 0, 0, 0) then
    begin

      if FirmarAcuseRecibo(Context.Request.Body) then
      begin
        Context.Response.ContentType := 'application/xml; charset=utf-8';
        Context.Response.Content := XMLsign;
      end
      else
        Render('HTTP 400');

    end;
  end
  else
    Render('No se ha verificado el token o ha expirado.');
end;

function IsXMLFileSigned(const Filename: string): Boolean;
var
  XMLDocument: IXMLDOMDocument3;
  SignatureNode: IXMLDOMNode;
begin
  Result := False;

  try
    // Cargar el archivo XML
    XMLDocument := CoDOMDocument60.Create;
    XMLDocument.async := False;
    XMLDocument.load(Filename);

    // Obtener el nodo de la firma
    SignatureNode := XMLDocument.selectSingleNode('//Signature');
    if Assigned(SignatureNode) then
      Result := true;
  except
    // En caso de error al cargar el archivo XML o encontrar el nodo de la firma
    Result := False;
  end;
end;

procedure TMyController.AuthenticateToken(var Token: string);
begin

  Context.Response.SetCustomHeader('Access-Control-Allow-Origin', '*');

  // Aquí debes implementar la lógica de autenticación del token
  // Puedes realizar verificaciones adicionales, como consultar una base de datos o validar la estructura del token.

  // Verificar si se ha ingresado un token
  if Token <> '' then
  begin
    // Verificar la longitud del token
    if Length(Token) = 289 then
    begin
      Render('Token autenticado');

      // Borrar el token después de verificarlo
      Token := '';

      // Establecer el estado de verificación del token
      TokenVerified := true;
      TokenVerificationTime := Now; // Registrar el tiempo de verificación
    end
    else
      Render('Token no autenticado');
  end
  else
    Render('No se ha ingresado ningún token');
end;

end.
