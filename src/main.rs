use guid_create::GUID;
use hex::FromHex;
use jsonwebtoken::*;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let quote_hex = "0100000002000000E811000000000000030002000000000005000A00939A7233F79C4CA9940A0DB3957F060709BFEC8156DB138E035639B0473295A20000000011110305FF8006000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000700000000000000AAC7E4D64861B132E4CAE990DF21C5347DD052BD9DAD5AFDFF12B7E7EBFE1C9D000000000000000000000000000000000000000000000000000000000000000062BA6BCAB59700C340BDBCD36BF74C6E0D6892CDF91671DCA93BCBFFF81EF9F20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003C88E0250887C7B214D15F36C84430596DAE49D762CF6FE3E3B96EC572DFB2100000000000000000000000000000000000000000000000000000000000000003410000069A83FB1117A14204F594A53C0799324B30E02F548A5166FEFDF8870E55053D433C93F1D2054BDEFC6EF597B969F798EAE221BEF54A934AA29A8C6585FD1E5887B33C2436AE26B1968527DC8778AD7A92FCD4D161E628F996208461DFA3741D432CF9B46B12343787028C2D785E56CED35EAEBFACDF56CF3F77A407D85EC685411110305FF800600000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000070000000000000060D85AF28BE8D1C40A08D98B009D5F8ACC1384A385CF460800E478791D1A979C00000000000000000000000000000000000000000000000000000000000000008C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010005000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006812D40A870264B0863A1A182ABC431DE0F0D6E555E3C34AF335CE5CEE750EDA00000000000000000000000000000000000000000000000000000000000000005279D008B036DC6AEC03427945E45CD9FFB3D14323689C3876437F9DC193D9DC3E17A549F66AD0801D5295471D5761DFD32975E6C06AB5C06098C82E8390E34B2000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F0500CC0D00002D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D49494567544343424365674177494241674956414E65704C52412F737547685A3564446E4A436E4A637041737648454D416F4743437147534D343942414D430A4D484578497A416842674E5642414D4D476B6C756447567349464E48574342515130736755484A765932567A6332397949454E424D526F77474159445651514B0A4442464A626E526C6243424462334A7762334A6864476C76626A45554D424947413155454277774C553246756447456751327868636D4578437A414A42674E560A4241674D416B4E424D517377435159445651514745774A56557A4165467730794D5441794D6A41784E4455324E444661467730794F4441794D6A41784E4455320A4E4446614D484178496A416742674E5642414D4D47556C756447567349464E4857434251513073675132567964476C6D61574E6864475578476A415942674E560A42416F4D45556C756447567349454E76636E4276636D4630615739754D5251774567594456515148444174545957353059534244624746795954454C4D416B470A413155454341774351304578437A414A42674E5642415954416C56544D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A304441516344516741450A7A7552512F654E59516F504D696F595753316374696B716B7334575545516638323531304876746F4A55664958554C576C6C6262716B6A7357613439773034340A6131584A685377424E465A2F4A6F4A6D59564B31584B4F434170737767674B584D42384741315564497751594D426141464E446F71747031312F6B75535265590A504873555A644456386C6C4E4D46384741315564487752594D465977564B42536F464347546D68306448427A4F693876595842704C6E527964584E305A57527A0A5A584A3261574E6C63793570626E526C6243356A62323076633264344C324E6C636E52705A6D6C6A5958527062323476646A497663474E7259334A7350324E680A5058427962324E6C63334E76636A416442674E564851344546675155646D7666734F7065516A7170456C3148367471446477534A4C32387744675944565230500A4151482F42415144416762414D41774741315564457745422F7751434D4141776767485542676B71686B69472B45304244514545676748464D494942775441650A42676F71686B69472B45304244514542424242586277374D4F524D336A513435465366734A3848494D4949425A41594B4B6F5A496876684E41513042416A43430A415651774541594C4B6F5A496876684E4151304241674543415245774541594C4B6F5A496876684E4151304241674943415245774541594C4B6F5A496876684E0A4151304241674D43415149774541594C4B6F5A496876684E4151304241675143415151774541594C4B6F5A496876684E4151304241675543415145774551594C0A4B6F5A496876684E4151304241675943416743414D42414743797147534962345451454E41514948416745474D42414743797147534962345451454E415149490A416745414D42414743797147534962345451454E4151494A416745414D42414743797147534962345451454E4151494B416745414D42414743797147534962340A5451454E4151494C416745414D42414743797147534962345451454E4151494D416745414D42414743797147534962345451454E4151494E416745414D4241470A43797147534962345451454E4151494F416745414D42414743797147534962345451454E41514950416745414D42414743797147534962345451454E415149510A416745414D42414743797147534962345451454E415149524167454B4D42384743797147534962345451454E41514953424241524551494541594147414141410A41414141414141414D42414743697147534962345451454E41514D45416741414D42514743697147534962345451454E415151454267435162745541414441500A42676F71686B69472B45304244514546436745414D416F4743437147534D343942414D43413067414D45554349425963465A4877494E472B55696355756B6A730A52646B682F3171383832534E654E3550304268306875795941694541704A4E44477869526A55474172795A474D364C67506C71626B7A76554F6B712F797A4D6E0A6B67547148444D3D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949436C7A4343416A36674177494241674956414E446F71747031312F6B7553526559504873555A644456386C6C4E4D416F4743437147534D343942414D430A4D476778476A415942674E5642414D4D45556C756447567349464E48574342536232393049454E424D526F77474159445651514B4442464A626E526C624342440A62334A7762334A6864476C76626A45554D424947413155454277774C553246756447456751327868636D4578437A414A42674E564241674D416B4E424D5173770A435159445651514745774A56557A4165467730784F4441314D6A45784D4451314D4468614677307A4D7A41314D6A45784D4451314D4468614D484578497A41680A42674E5642414D4D476B6C756447567349464E48574342515130736755484A765932567A6332397949454E424D526F77474159445651514B4442464A626E526C0A6243424462334A7762334A6864476C76626A45554D424947413155454277774C553246756447456751327868636D4578437A414A42674E564241674D416B4E420A4D517377435159445651514745774A56557A425A4D424D4742797147534D34394167454743437147534D34394177454841304941424C39712B4E4D7032494F670A74646C31626B2F75575A352B5447516D38614369387A373866732B664B435133642B75447A586E56544154325A68444369667949754A77764E33774E427039690A484253534D4A4D4A72424F6A6762737767626777487759445652306A42426777466F4155496D554D316C71644E496E7A6737535655723951477A6B6E427177770A556759445652306642457377535442486F45576751345A426148523063484D364C79396A5A584A3061575A70593246305A584D7564484A316333526C5A484E6C0A636E5A705932567A4C6D6C75644756734C6D4E766253394A626E526C62464E4857464A76623352445153356A636D7777485159445652304F42425945464E446F0A71747031312F6B7553526559504873555A644456386C6C4E4D41344741315564447745422F77514541774942426A415342674E5648524D4241663845434441470A4151482F416745414D416F4743437147534D343942414D43413063414D45514349432F396A2B3834542B487A74564F2F734F5142574A6253642B2F327565784B0A342B6141306A6346424C63704169413364684D72463563443532743646714D764149706A385864476D79326265656C6A4C4A4B2B707A706352413D3D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949436A6A4343416A53674177494241674955496D554D316C71644E496E7A6737535655723951477A6B6E42717777436759494B6F5A497A6A3045417749770A614445614D4267474131554541777752535735305A5777675530645949464A766233516751304578476A415942674E5642416F4D45556C756447567349454E760A636E4276636D4630615739754D5251774567594456515148444174545957353059534244624746795954454C4D416B47413155454341774351304578437A414A0A42674E5642415954416C56544D423458445445344D4455794D5445774E4445784D566F5844544D7A4D4455794D5445774E4445784D466F77614445614D4267470A4131554541777752535735305A5777675530645949464A766233516751304578476A415942674E5642416F4D45556C756447567349454E76636E4276636D46300A615739754D5251774567594456515148444174545957353059534244624746795954454C4D416B47413155454341774351304578437A414A42674E56424159540A416C56544D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A3044415163445167414543366E45774D4449595A4F6A2F69505773437A61454B69370A314F694F534C52466857476A626E42564A66566E6B59347533496A6B4459594C304D784F346D717379596A6C42616C54565978465032734A424B357A6C4B4F420A757A43427544416642674E5648534D4547444157674251695A517A575770303069664F44744A5653763141624F5363477244425342674E5648523845537A424A0A4D45656752614244686B466F64485277637A6F764C324E6C636E52705A6D6C6A5958526C63793530636E567A6447566B63325679646D6C6A5A584D75615735300A5A577775593239744C306C756447567355306459556D397664454E424C6D4E796244416442674E564851344546675155496D554D316C71644E496E7A673753560A55723951477A6B6E4271777744675944565230504151482F42415144416745474D42494741315564457745422F7751494D4159424166384341514577436759490A4B6F5A497A6A30454177494453414177525149675151732F30387279636450617543466B3855505158434D416C736C6F4265374E7761514754636470613045430A495143557438534776784B6D6A70634D2F7A3057503944766F3868326B3564753169574464426B416E2B306969413D3D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A00";
    let enclave_held_data_hex = "2D2D2D2D2D424547494E205055424C4943204B45592D2D2D2D2D0A4D494942496A414E42676B71686B6947397730424151454641414F43415138414D49494243674B434151454170554E694E764D476A46587674464761655734330A6955384E454134507038526D70716F38454B306A5A4D64472B575142635165656B445736337167644A7772536E62757A6F6B43796134493051707645696F71300A44546F7530484373624E3158566B655679697A377641366879647567387274552B2B2F76555865692B564D34385865745950726B754F694538675970354332430A365243736875474F6D59427869435161656F4E4D4F3655492B6E65484D654E576F7153306C43537978555839736944317761437436577444446D736C552B64580A2B6C7A6B73527750566E502F706C4272746865536E62595637504D663852446E5233786255502B576B36644F416A713168714F2B4F625A36575159555A746B710A795447566E392F6C7765573647527A35394F59485664424369384D74477452534837745436644D45395058416F5341456A6655707348504A3034372B6E4E65790A32514944415141420A2D2D2D2D2D454E44205055424C4943204B45592D2D2D2D2D0A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    attest(quote_hex, enclave_held_data_hex).await?;
    Ok(())
}

async fn attest(
    quote_hex: &str,
    enclave_held_data_hex: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let quote_base64 = hex_to_base64(quote_hex)?;
    let enclave_held_data_base64 = hex_to_base64(enclave_held_data_hex)?;

    let body = json! {
        {
            "Report": quote_base64,
            "RuntimeData" : {
                "Data": enclave_held_data_base64,
                "DataType": "Binary"
            },
        }
    };
    // println!("Body: {}", serde_json::to_string(&body)?);

    let client = reqwest::Client::new();
    let enclave_request = client.post("https://hackprovider.wus.attest.azure.net:443/attest/OpenEnclave?api-version=2020-10-01")
        // .header("Authorization", format!("Bearer {}", get_aad_token().await?))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body)?)
        .send().await?;

    println!("Enclave Response: {:#?}", enclave_request);

    let body = enclave_request.text().await?;
    println!("Enclave Response Body: {:#?}", body);

    Ok(body)
}

fn hex_to_base64(hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(base64::encode_config(
        Vec::from_hex(hex)?,
        base64::URL_SAFE_NO_PAD,
    ))
}

async fn get_aad_token() -> Result<String, Box<dyn std::error::Error>> {
    let tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let client_id = "1acd55d3-138b-4538-8521-63215c58e9df";

    let login_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant
    );

    // ========================== Make Cert JWT ================================================
    // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
    // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

    // TODO: use better exp values
    let my_claims = Claims {
        aud: login_url.clone(),
        exp: 10000000000,
        iss: client_id.to_owned(),
        jti: GUID::rand().to_string(),
        nbf: 0,
        sub: client_id.to_owned(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.x5t = Some("2YcP/RtHg9MI002scO6552MBLaQ=".to_owned());

    let cert_token = encode(
        &header,
        &my_claims,
        &EncodingKey::from_rsa_pem(include_bytes!(
            r#"C:\Users\Lee\Downloads\device-id.key.pem"#
        ))?,
    )?;
    // println!("Cert JWT: {}", cert_token);

    // ========================== Get token ================================================
    let client = reqwest::Client::new();

    let scope = "https://management.azure.com/.default";
    // let scope = "https://hackprovider.wus.attest.azure.net";

    let body = &[
        ("client_id", client_id),
        ("scope", scope),
        ("grant_type", "client_credentials"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &cert_token),
    ];

    let get_token = client.post(&login_url).form(body).send().await?;
    // println!("AAD Token: {:#?}", get_token.text().await);

    let token: TokenResponse = get_token.json().await?;
    // println!("AAD Token: {}", token.access_token);

    Ok(token.access_token)
}

#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    token_type: String,
    expires_in: u64,
    // ext_expires_in: u64,
    access_token: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    aud: String,
    exp: usize,
    iss: String,
    jti: String,
    nbf: usize,
    sub: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding() {
        let input = "0100000002000000E811000000000000030002000000000005000A00939A7233F79C4CA9940A0DB3957F060709BFEC8156DB138E035639B0473295A20000000011110305FF8006000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000700000000000000AAC7E4D64861B132E4CAE990DF21C5347DD052BD9DAD5AFDFF12B7E7EBFE1C9D000000000000000000000000000000000000000000000000000000000000000062BA6BCAB59700C340BDBCD36BF74C6E0D6892CDF91671DCA93BCBFFF81EF9F20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003C88E0250887C7B214D15F36C84430596DAE49D762CF6FE3E3B96EC572DFB2100000000000000000000000000000000000000000000000000000000000000003410000069A83FB1117A14204F594A53C0799324B30E02F548A5166FEFDF8870E55053D433C93F1D2054BDEFC6EF597B969F798EAE221BEF54A934AA29A8C6585FD1E5887B33C2436AE26B1968527DC8778AD7A92FCD4D161E628F996208461DFA3741D432CF9B46B12343787028C2D785E56CED35EAEBFACDF56CF3F77A407D85EC685411110305FF800600000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000070000000000000060D85AF28BE8D1C40A08D98B009D5F8ACC1384A385CF460800E478791D1A979C00000000000000000000000000000000000000000000000000000000000000008C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010005000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006812D40A870264B0863A1A182ABC431DE0F0D6E555E3C34AF335CE5CEE750EDA00000000000000000000000000000000000000000000000000000000000000005279D008B036DC6AEC03427945E45CD9FFB3D14323689C3876437F9DC193D9DC3E17A549F66AD0801D5295471D5761DFD32975E6C06AB5C06098C82E8390E34B2000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F0500CC0D00002D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D49494567544343424365674177494241674956414E65704C52412F737547685A3564446E4A436E4A637041737648454D416F4743437147534D343942414D430A4D484578497A416842674E5642414D4D476B6C756447567349464E48574342515130736755484A765932567A6332397949454E424D526F77474159445651514B0A4442464A626E526C6243424462334A7762334A6864476C76626A45554D424947413155454277774C553246756447456751327868636D4578437A414A42674E560A4241674D416B4E424D517377435159445651514745774A56557A4165467730794D5441794D6A41784E4455324E444661467730794F4441794D6A41784E4455320A4E4446614D484178496A416742674E5642414D4D47556C756447567349464E4857434251513073675132567964476C6D61574E6864475578476A415942674E560A42416F4D45556C756447567349454E76636E4276636D4630615739754D5251774567594456515148444174545957353059534244624746795954454C4D416B470A413155454341774351304578437A414A42674E5642415954416C56544D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A304441516344516741450A7A7552512F654E59516F504D696F595753316374696B716B7334575545516638323531304876746F4A55664958554C576C6C6262716B6A7357613439773034340A6131584A685377424E465A2F4A6F4A6D59564B31584B4F434170737767674B584D42384741315564497751594D426141464E446F71747031312F6B75535265590A504873555A644456386C6C4E4D46384741315564487752594D465977564B42536F464347546D68306448427A4F693876595842704C6E527964584E305A57527A0A5A584A3261574E6C63793570626E526C6243356A62323076633264344C324E6C636E52705A6D6C6A5958527062323476646A497663474E7259334A7350324E680A5058427962324E6C63334E76636A416442674E564851344546675155646D7666734F7065516A7170456C3148367471446477534A4C32387744675944565230500A4151482F42415144416762414D41774741315564457745422F7751434D4141776767485542676B71686B69472B45304244514545676748464D494942775441650A42676F71686B69472B45304244514542424242586277374D4F524D336A513435465366734A3848494D4949425A41594B4B6F5A496876684E41513042416A43430A415651774541594C4B6F5A496876684E4151304241674543415245774541594C4B6F5A496876684E4151304241674943415245774541594C4B6F5A496876684E0A4151304241674D43415149774541594C4B6F5A496876684E4151304241675143415151774541594C4B6F5A496876684E4151304241675543415145774551594C0A4B6F5A496876684E4151304241675943416743414D42414743797147534962345451454E41514948416745474D42414743797147534962345451454E415149490A416745414D42414743797147534962345451454E4151494A416745414D42414743797147534962345451454E4151494B416745414D42414743797147534962340A5451454E4151494C416745414D42414743797147534962345451454E4151494D416745414D42414743797147534962345451454E4151494E416745414D4241470A43797147534962345451454E4151494F416745414D42414743797147534962345451454E41514950416745414D42414743797147534962345451454E415149510A416745414D42414743797147534962345451454E415149524167454B4D42384743797147534962345451454E41514953424241524551494541594147414141410A41414141414141414D42414743697147534962345451454E41514D45416741414D42514743697147534962345451454E415151454267435162745541414441500A42676F71686B69472B45304244514546436745414D416F4743437147534D343942414D43413067414D45554349425963465A4877494E472B55696355756B6A730A52646B682F3171383832534E654E3550304268306875795941694541704A4E44477869526A55474172795A474D364C67506C71626B7A76554F6B712F797A4D6E0A6B67547148444D3D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949436C7A4343416A36674177494241674956414E446F71747031312F6B7553526559504873555A644456386C6C4E4D416F4743437147534D343942414D430A4D476778476A415942674E5642414D4D45556C756447567349464E48574342536232393049454E424D526F77474159445651514B4442464A626E526C624342440A62334A7762334A6864476C76626A45554D424947413155454277774C553246756447456751327868636D4578437A414A42674E564241674D416B4E424D5173770A435159445651514745774A56557A4165467730784F4441314D6A45784D4451314D4468614677307A4D7A41314D6A45784D4451314D4468614D484578497A41680A42674E5642414D4D476B6C756447567349464E48574342515130736755484A765932567A6332397949454E424D526F77474159445651514B4442464A626E526C0A6243424462334A7762334A6864476C76626A45554D424947413155454277774C553246756447456751327868636D4578437A414A42674E564241674D416B4E420A4D517377435159445651514745774A56557A425A4D424D4742797147534D34394167454743437147534D34394177454841304941424C39712B4E4D7032494F670A74646C31626B2F75575A352B5447516D38614369387A373866732B664B435133642B75447A586E56544154325A68444369667949754A77764E33774E427039690A484253534D4A4D4A72424F6A6762737767626777487759445652306A42426777466F4155496D554D316C71644E496E7A6737535655723951477A6B6E427177770A556759445652306642457377535442486F45576751345A426148523063484D364C79396A5A584A3061575A70593246305A584D7564484A316333526C5A484E6C0A636E5A705932567A4C6D6C75644756734C6D4E766253394A626E526C62464E4857464A76623352445153356A636D7777485159445652304F42425945464E446F0A71747031312F6B7553526559504873555A644456386C6C4E4D41344741315564447745422F77514541774942426A415342674E5648524D4241663845434441470A4151482F416745414D416F4743437147534D343942414D43413063414D45514349432F396A2B3834542B487A74564F2F734F5142574A6253642B2F327565784B0A342B6141306A6346424C63704169413364684D72463563443532743646714D764149706A385864476D79326265656C6A4C4A4B2B707A706352413D3D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949436A6A4343416A53674177494241674955496D554D316C71644E496E7A6737535655723951477A6B6E42717777436759494B6F5A497A6A3045417749770A614445614D4267474131554541777752535735305A5777675530645949464A766233516751304578476A415942674E5642416F4D45556C756447567349454E760A636E4276636D4630615739754D5251774567594456515148444174545957353059534244624746795954454C4D416B47413155454341774351304578437A414A0A42674E5642415954416C56544D423458445445344D4455794D5445774E4445784D566F5844544D7A4D4455794D5445774E4445784D466F77614445614D4267470A4131554541777752535735305A5777675530645949464A766233516751304578476A415942674E5642416F4D45556C756447567349454E76636E4276636D46300A615739754D5251774567594456515148444174545957353059534244624746795954454C4D416B47413155454341774351304578437A414A42674E56424159540A416C56544D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A3044415163445167414543366E45774D4449595A4F6A2F69505773437A61454B69370A314F694F534C52466857476A626E42564A66566E6B59347533496A6B4459594C304D784F346D717379596A6C42616C54565978465032734A424B357A6C4B4F420A757A43427544416642674E5648534D4547444157674251695A517A575770303069664F44744A5653763141624F5363477244425342674E5648523845537A424A0A4D45656752614244686B466F64485277637A6F764C324E6C636E52705A6D6C6A5958526C63793530636E567A6447566B63325679646D6C6A5A584D75615735300A5A577775593239744C306C756447567355306459556D397664454E424C6D4E796244416442674E564851344546675155496D554D316C71644E496E7A673753560A55723951477A6B6E4271777744675944565230504151482F42415144416745474D42494741315564457745422F7751494D4159424166384341514577436759490A4B6F5A497A6A30454177494453414177525149675151732F30387279636450617543466B3855505158434D416C736C6F4265374E7761514754636470613045430A495143557438534776784B6D6A70634D2F7A3057503944766F3868326B3564753169574464426B416E2B306969413D3D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A00";
        let expected = "AQAAAAIAAADoEQAAAAAAAAMAAgAAAAAABQAKAJOacjP3nEyplAoNs5V_BgcJv-yBVtsTjgNWObBHMpWiAAAAABERAwX_gAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAABwAAAAAAAACqx-TWSGGxMuTK6ZDfIcU0fdBSvZ2tWv3_Erfn6_4cnQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYrpryrWXAMNAvbzTa_dMbg1oks35FnHcqTvL__ge-fIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8iOAlCIfHshTRXzbIRDBZba5J12LPb-PjuW7Fct-yEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQQAABpqD-xEXoUIE9ZSlPAeZMksw4C9UilFm_v34hw5VBT1DPJPx0gVL3vxu9Ze5afeY6uIhvvVKk0qimoxlhf0eWIezPCQ2riaxloUn3Id4rXqS_NTRYeYo-ZYghGHfo3QdQyz5tGsSNDeHAowteF5WztNerr-s31bPP3ekB9hexoVBERAwX_gAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABUAAAAAAAAABwAAAAAAAABg2Fryi-jRxAoI2YsAnV-KzBOEo4XPRggA5Hh5HRqXnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjE9XddeWUD6WE393xoqCmgBWrI3tcBQLCBsJRJDFe_8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaBLUCocCZLCGOhoYKrxDHeDw1uVV48NK8zXOXO51DtoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJ50AiwNtxq7ANCeUXkXNn_s9FDI2icOHZDf53Bk9ncPhelSfZq0IAdUpVHHVdh39MpdebAarXAYJjILoOQ40sgAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fBQDMDQAALS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVnVENDQkNlZ0F3SUJBZ0lWQU5lcExSQS9zdUdoWjVkRG5KQ25KY3BBc3ZIRU1Bb0dDQ3FHU000OUJBTUMKTUhFeEl6QWhCZ05WQkFNTUdrbHVkR1ZzSUZOSFdDQlFRMHNnVUhKdlkyVnpjMjl5SUVOQk1Sb3dHQVlEVlFRSwpEQkZKYm5SbGJDQkRiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WCkJBZ01Ba05CTVFzd0NRWURWUVFHRXdKVlV6QWVGdzB5TVRBeU1qQXhORFUyTkRGYUZ3MHlPREF5TWpBeE5EVTIKTkRGYU1IQXhJakFnQmdOVkJBTU1HVWx1ZEdWc0lGTkhXQ0JRUTBzZ1EyVnlkR2xtYVdOaGRHVXhHakFZQmdOVgpCQW9NRVVsdWRHVnNJRU52Y25CdmNtRjBhVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHCkExVUVDQXdDUTBFeEN6QUpCZ05WQkFZVEFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUKenVSUS9lTllRb1BNaW9ZV1MxY3Rpa3FrczRXVUVRZjgyNTEwSHZ0b0pVZklYVUxXbGxiYnFranNXYTQ5dzA0NAphMVhKaFN3Qk5GWi9Kb0ptWVZLMVhLT0NBcHN3Z2dLWE1COEdBMVVkSXdRWU1CYUFGTkRvcXRwMTEva3VTUmVZClBIc1VaZERWOGxsTk1GOEdBMVVkSHdSWU1GWXdWS0JTb0ZDR1RtaDBkSEJ6T2k4dllYQnBMblJ5ZFhOMFpXUnoKWlhKMmFXTmxjeTVwYm5SbGJDNWpiMjB2YzJkNEwyTmxjblJwWm1sallYUnBiMjR2ZGpJdmNHTnJZM0pzUDJOaApQWEJ5YjJObGMzTnZjakFkQmdOVkhRNEVGZ1FVZG12ZnNPcGVRanFwRWwxSDZ0cURkd1NKTDI4d0RnWURWUjBQCkFRSC9CQVFEQWdiQU1Bd0dBMVVkRXdFQi93UUNNQUF3Z2dIVUJna3Foa2lHK0UwQkRRRUVnZ0hGTUlJQndUQWUKQmdvcWhraUcrRTBCRFFFQkJCQlhidzdNT1JNM2pRNDVGU2ZzSjhISU1JSUJaQVlLS29aSWh2aE5BUTBCQWpDQwpBVlF3RUFZTEtvWklodmhOQVEwQkFnRUNBUkV3RUFZTEtvWklodmhOQVEwQkFnSUNBUkV3RUFZTEtvWklodmhOCkFRMEJBZ01DQVFJd0VBWUxLb1pJaHZoTkFRMEJBZ1FDQVFRd0VBWUxLb1pJaHZoTkFRMEJBZ1VDQVFFd0VRWUwKS29aSWh2aE5BUTBCQWdZQ0FnQ0FNQkFHQ3lxR1NJYjRUUUVOQVFJSEFnRUdNQkFHQ3lxR1NJYjRUUUVOQVFJSQpBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUpBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUtBZ0VBTUJBR0N5cUdTSWI0ClRRRU5BUUlMQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlNQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlOQWdFQU1CQUcKQ3lxR1NJYjRUUUVOQVFJT0FnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJUEFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJUQpBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSVJBZ0VLTUI4R0N5cUdTSWI0VFFFTkFRSVNCQkFSRVFJRUFZQUdBQUFBCkFBQUFBQUFBTUJBR0NpcUdTSWI0VFFFTkFRTUVBZ0FBTUJRR0NpcUdTSWI0VFFFTkFRUUVCZ0NRYnRVQUFEQVAKQmdvcWhraUcrRTBCRFFFRkNnRUFNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJQlljRlpId0lORytVaWNVdWtqcwpSZGtoLzFxODgyU05lTjVQMEJoMGh1eVlBaUVBcEpOREd4aVJqVUdBcnlaR002TGdQbHFia3p2VU9rcS95ek1uCmtnVHFIRE09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNsekNDQWo2Z0F3SUJBZ0lWQU5Eb3F0cDExL2t1U1JlWVBIc1VaZERWOGxsTk1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFExTURoYUZ3MHpNekExTWpFeE1EUTFNRGhhTUhFeEl6QWgKQmdOVkJBTU1Ha2x1ZEdWc0lGTkhXQ0JRUTBzZ1VISnZZMlZ6YzI5eUlFTkJNUm93R0FZRFZRUUtEQkZKYm5SbApiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CCk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTDlxK05NcDJJT2cKdGRsMWJrL3VXWjUrVEdRbThhQ2k4ejc4ZnMrZktDUTNkK3VEelhuVlRBVDJaaERDaWZ5SXVKd3ZOM3dOQnA5aQpIQlNTTUpNSnJCT2pnYnN3Z2Jnd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3ClVnWURWUjBmQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpYTXVkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2YjNSRFFTNWpjbXd3SFFZRFZSME9CQllFRk5EbwpxdHAxMS9rdVNSZVlQSHNVWmREVjhsbE5NQTRHQTFVZER3RUIvd1FFQXdJQkJqQVNCZ05WSFJNQkFmOEVDREFHCkFRSC9BZ0VBTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUMvOWorODRUK0h6dFZPL3NPUUJXSmJTZCsvMnVleEsKNCthQTBqY0ZCTGNwQWlBM2RoTXJGNWNENTJ0NkZxTXZBSXBqOFhkR215MmJlZWxqTEpLK3B6cGNSQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqakNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdOREV4TVZvWERUTXpNRFV5TVRFd05ERXhNRm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtTnliREFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNBQXdSUUlnUVFzLzA4cnljZFBhdUNGazhVUFFYQ01BbHNsb0JlN053YVFHVGNkcGEwRUMKSVFDVXQ4U0d2eEttanBjTS96MFdQOUR2bzhoMms1ZHUxaVdEZEJrQW4rMGlpQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAA"; // base64::encode_config(quote_hex, base64::URL_SAFE);

        assert_eq!(hex_to_base64(input).unwrap(), expected);
    }
}
