/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util.security.mldsa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.stream.Stream;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.SunSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleSecurityProviderRegistrar;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

@Tag("NoIoTestCase")
class MLDSATest extends JUnitTestSupport {
    // NIST ACVP-Server ML-DSA-keyGen-FIPS204/internalProjection.json, vsId 42.
    static Stream<Arguments> vectors() {
        return Stream.of(
                // ML-DSA-44, tcId 1
                Arguments.of(MLDSAParameterSets.ML_DSA_44,
                        "0B89806F0EEC39F2891116152ED4319D4260DFB8AC0710765BD497E6E1DE17783CF81E435A412EABEF5DB3AF5D15867B"
                                                           + "BB4C60F8CF98BA31BAD6D41A5F8EB0C11B632C3F19D844A223C353BD182883DCF13B5C97823D0C0E6902DB25AD8D344A"
                                                           + "37F59F4AFACA5BC8874792DA1E6A3EAE742AB7034B20A4AB75A93BCA4B68002DD242CED348920B7E5ABF645A0E2E7961"
                                                           + "7BCB3EE7BA972B3E718D3EFFC59B1869814BA3F526927477B12BF25CBAD8B04B09905FDAD3820715A8B9A905DE1CD65E"
                                                           + "FF6B0B0886305EFB6CFEEC9E90B5EF9A5AAEC45C753298E8DF9B017CE0FEC9B7431B20775CE8CB11F1F42D1D9FE936D0"
                                                           + "803196E71ADDC26CC430CC3B69760C7CCAFAB7651E21BAA28F92BBFF1C4A6EEF156D6F08F80B5E3B6FC943E6E984378B"
                                                           + "90888D09A6EA38B0BA86A3446211452E076DC9F65620014205D5271C7A44FEC3CC5375EB246AFFC11B26CAFB8B96CEE3"
                                                           + "A68E31642E3D69B9130795F25ED818EBB211CD8BE648ADB5C8A120C8186017727FBCAB31C7425C08FE9195DE6BDBADA5"
                                                           + "778D727EE5CDE0674FACB7AB81786357B529C71DDB24DF770E8E95E5F3112BD297B352CB91B08ED1097A98E87BD7CE42"
                                                           + "35B8DD42292CD4C59D87C1F0FF00734AA22D7CAE4361ADC47742C897601048526702538828BA3C3A959990C0E99463FD"
                                                           + "22417E147FF2DAA74C0C8D3A06E9703A2E160590086DB8011A3D9CEC5AE6348706F87CB2379632CE56E660A0BA1B30E3"
                                                           + "846C5B5C6C0339DD993E543A5322AF5A11FC7040A2DF23A0B43E882D7A0FF4431A723BBB918AFF7F14BC045CBE94BCAB"
                                                           + "27AE3109147B588665EF486006562B1297016EFDE787B46237060EE431E0F011166F916AA0789A7647103B7400A1CBCF"
                                                           + "0E22BD7B6DD2BB3EC51EC98F0EC6A5BAA4CDC83F993D302F8FA849F2046B78AA32F0B3751885ECB941799E250E6546DC"
                                                           + "A5C20C24845190F239EDC20DDA77353D555DE61509CA6D3C6DC3195BBC6F1703CB03EAD5E7FCBCF5D196E9AB71522408"
                                                           + "E11D6337C74F9A31EB22AD084A19132BF72E7076A9743ED070ABA78789791824E050CD27694C2648263D1200811FA1B8"
                                                           + "1A00B8FC09CB7A338795E54F6598D7753395F05C60E6EBA9630912B7AA8CAAB3017565DEF72C7929F4E7736C2B8043FE"
                                                           + "B448801E2DED704E834294B69F6A109C0968214FDC5C3FF0D1B1555D617E16DF61829231962C59B22A10FE400F8B8CB2"
                                                           + "A3F19FB4B2E8D087F22687506E7F0D061857D1C1789C7F55B899FF4B322982D64BD0AA751D5BEE320B135C7F5DDCD5E6"
                                                           + "245B57DD22F44042F2BA6DE942365A59FD0C6B0F20C07B71277C6EE7DD9D225032605AED1D3CF8242EB85C33A0AFC3AB"
                                                           + "42764088D8F4A80FAF804CD84360B2055181E58A0B5AD4C367ABC667982045AD0FD7E048AF8C326D5DB60233302B107E"
                                                           + "515B15B0F90E5F348C54192B559B4C0A86CDF0719387EA3FF6B1D60B324A98963C56927E2B8DD5A39AC792AEB85EBDBD"
                                                           + "8DC34B395C2B4DEF4D853AC21A7660348EA8C96C943DE0BAFF3AA6849179E5EF2BAA1731C81C605BEC3860FC4A6A08CC"
                                                           + "9F75BDE9533511780FF1E0B01D34C0DC3EB80A7E2F52A7A4B815DDA98EA775DFE0C5B3D419B05934DDA05A9616C0978C"
                                                           + "C99CC8D7B68227BD846419D765956C3D7AA811CE60AF22DF322FEF0DCE38C4278E0237F1D29EF139E201C8ECB4D36E79"
                                                           + "910D06C5CA4CAA8C2886B96DE6EDD40D2499E30EB942F22BEBF6ED5C8E37DF9557E74D67DC467BAAFA68F1CE37C8BD9B"
                                                           + "3A4F9DE71670128125AA16ACA7232239575E1C6819C820AD16832F23647DD53C5740A8552F86901AA4F883EFD5A3EFD7"
                                                           + "C3BF458C5122712D44BE43306C9B8264"),
                // ML-DSA-65, tcId 26
                Arguments.of(MLDSAParameterSets.ML_DSA_65,
                        "36DB0B5DCE98BD190CB139E80B71B49C7D7040B71C5A1F3412C46BDE939192B1B57CCB88AC2714C1240CB0EB62C689E0"
                                                           + "31AEA3D9F3EB3ED7BFA45931D288DCAE3413199B31A7032560DCE8A61E195D13A1440615C2F3AA7DD28C5B1B742BFA40"
                                                           + "0052186721F13D3DF9DCFAEE348B10D66913C7148913E085E1A4A03C659398DADC6A8E0E0C1A7F9F44D30436DB90FD65"
                                                           + "A6AB8F36137338255653BAAE8DA21526A333426DBD9F76CCE0F43212643E854D772018B35CE726BCAAA5AB0651BAF8C1"
                                                           + "22E13929BB35B6E4963DF2595FDC7237CDAA7234BF776B07F353CCDBA12AD3E025138E3492D7F8E929DB55DC23E23075"
                                                           + "F66D57A10492E6A10AE7B758ACC2291CA18BA1CA07A5B574AB6D8AAC18B9524990AD2F110225B7D82F696300A660A166"
                                                           + "AD35B3C57ECBAB77117C79656FA8AE2A19A7DEFB2AFD2AF54683D043BE0F933B8EAE0D591448ED55D00068CD9FE10B06"
                                                           + "7FCFAAC53AEDB1E9B667E36C4E30231F85C7AA0A474AF2FA4776226F4479555E155528D78B98183CBDF7FAE4E7301140"
                                                           + "F163EB71E991D15FAD4A0D2F25A5A62FA2E9BCC823CC2927662E40C538213DED9E2DF508E911E4924E507A50861FBB05"
                                                           + "0EDBBF56D937206F8FBC6F4CEAD4CD10D06B73AADCD4AA39703A7A2BFFAE68B7BAA47341B699DA9F3B167D4D90EFEE0A"
                                                           + "07EE3529A3B5E8648B9CB07EE973E1D8DCCF1D16E95092C4A0184CCB4902D6086D9F444ACA5FA45F43CA91B351E82585"
                                                           + "989FFCBD6D2C3471D6B8593AA46F29D0DD9B44E8AA4D8F9A0BC886BB7982C56AAB11E23BFDBD8BC674732FADACACAE25"
                                                           + "FA416B2D0CC7743827293336507DA4B14C1F0AA2E929AF975466DADC89A016F33A0CCA2D5C08114CF04B02358805A772"
                                                           + "536432C44DBE9886130D2D3A0FFA0E175875A2207686F5E562B879EB2957573AB706B942468C20CC69BC566D29D9F151"
                                                           + "F3CFAE71CC97CE4A30722D4679FC1C089B5009935931EE60AAC5496B0FD5F24E514C0E20FA1DCC7729184A50FC85FAD1"
                                                           + "D2F32F715FBF55666E49F5A19761F2DD1AA5D1A33C7916EB6A794981C0334176ABC493EF30D9EAEAAD42E705989DCFCD"
                                                           + "EB578529A700BD14076A348A2062D6483CC63CD7F55136587AAC0E531A06EB2DE74E61CFCBBCE18F2ADA5A741F683BF1"
                                                           + "01F71432EE659DD1508E0C8FB2400E0CCBE435DA3466D543D3EF5BA369E125C0B84D855EFE6D4A22FF929A7A7A984E44"
                                                           + "8D23871E09B88A0BC3F3B7DA55DD2EDFB5A6DAA102819FF50CD4DCCD0A95D2F27354668065D4A56C31FB18B92B2A8DB2"
                                                           + "C6453BAA9333AEA6EABB1BD6411D584DD5900262057A707F81CC5137DBDD9AC1079BB98DA78A8E4BD1B2E0546C2B3D95"
                                                           + "6FCC280D37D855E31F1E4315B387A742280F057F3219EAE512884AE7EC4D2E3A72265B1D0163FBCBF616B2E289B0EAF9"
                                                           + "C63437D50B7B50CE408F5B4562F2ABF510C19F5E8A0ACE264DB6E0F2A69A7D0B4A5E62A2B964F08C8FFE9C295F5773BD"
                                                           + "D7FAB054A13822D428FAE28AE5E4ADC9D9F6E4DFFC457A3E49F0BCF62B32961C4667B60960452AFD917FDD00D954FA30"
                                                           + "C8533E5629F90AF85948DC1BAD889F91832DDF9B738254C9E7939726C37AB4557C2CE363C1391816C467537B471E5985"
                                                           + "E8084C277B62BE514922D352E20689EABB3EB91C343F36E77B152D5E85AFD088F4D02E7024B248A7420F58C7EBBEB480"
                                                           + "CAE39B56164F5ACD37A4F56B3DB6E1CC6B7C8C96CD3C44A69D9AC99175257BAB7FD83C5B574B5C9702C0FD13A5B176C6"
                                                           + "0F82D2DFFF50C2AF25D96E0F8D27EC818D499E479B9642AED4A4A0E6AF5F14CC5E1299EABAE055EF3C763D1E350E2D76"
                                                           + "E92CEE47A4233368466A298AFB4CA108A325D2A4F8B79F21EE7349C1C186ECD7897F9886CF27EC01B05388870484867F"
                                                           + "84BAE2C016D04A3762241907C4DE207798DD125A2CEBB6C2982F779E04117BDD65CD7FF0361A59D3EC05F6D903B6D155"
                                                           + "54BEEFB6D40D96A0D4B37AE76C69C1B9592088B7DB878F95ABEDCB5FD5423ED93DF1B27D01A4DC9F4438E7C55F35B0AE"
                                                           + "B7395B08E1ECBF15CB2B61D043C0454AEAEF2D487093FA0D7DE3FC6CAF084B6A0F15A5CB05D9340D4E6763983DC45B78"
                                                           + "28539C77A60D5E081A03FE29949D916392B6D989B4C8C047E3635A76BA88AC18A7A18CCFF5C7E06B02A43D2DFF169FA4"
                                                           + "49739E382BD020E0963C14A9ACAE6B6561C722D2BDA183F33EE6A904DF0207F5B098E56335CC063F9640C4997F593218"
                                                           + "D502F6B382354C73979E93C4B1B2471965FFA5A0DC8EE8ECA9F5697E7EF08DC0EEFD9AD75CD4122194B450201DFD73CD"
                                                           + "A46A7B2478DF66129FBB9C75B774213F9615BD990F8D07501FED440FD25D6CB912B8ECFA678D887A4EE28677E6E0491D"
                                                           + "49EFC7A3B34B9815C5C22983DA280D0AFDE2324F5281BC8B796DDACFD82723BBD9AA34B0C96075B36848591E47B80086"
                                                           + "897846FA76D092BC8BC6200837BFB5545039F8602B7EA49F63C0C3B8317EEEB7612F8E818DDE09E43C7DA76FD2FF6847"
                                                           + "906A45DA3D993E8EAED9FB3B1E579D8CC6900C89522AAEB0B4A80DA1E66AB8DFD62DFE4E4D77A3A77E5BD669207C70AA"
                                                           + "8537DD6D80A647B0420D79531A7456052C3C989F0F08DE3D343C40067680B39ECE95A17AAC8A622D1D5D95B38CA0F11D"
                                                           + "94E5B0A7634EEF4055517ACE79F0DF1D7C172E0246ABB2AB6B135EE1A38A3B84F86FD7C3CAF178CD4446D0B554256AD4"
                                                           + "5C657E1192070ABA7DF480F489EBDF9753A79CCBC6AA893913C5F1271F1C6035"),
                // ML-DSA-87, tcId 51
                Arguments.of(MLDSAParameterSets.ML_DSA_87,
                        "A5787E8044248F3F85AAC54E9469FC98F1B1138CC127B120F9946C80B96E3D89CCFE38C995645D4B6A559EACB2AFB816"
                                                           + "21D765C6E42E73031D44CBE74D322C7B16249576EB4C500253538D1A2C6B408E681B93B9014E3147DFBECF9D9858F7E8"
                                                           + "635F8598BA6847127D216A888FFB1636CC761616A0389C39A4245695DDE0C86CCF8A3BC5A50EA6FDBCC0A34457D4DEFE"
                                                           + "35F775C5993685AEF2237C31912A619FF804AFE8AC3418C13502820AEE5249D6E577EE0B2A5E3E8DA2DD30F514A076B5"
                                                           + "0556D7581BA1F9B2E4671756A63065C20EBDA6EE2C33C9D97AB14C5F2204FC5359ADB2BDAA3AAB7AE1DACFF18A67D801"
                                                           + "BCB8F054BBC444F0FD0001A7908EBDCDF2B84F3C026EEC1282498D31AC33AE6A309ACAB17B70DC9F0EFBE52648D1AD2A"
                                                           + "4CD5964DC619B66CDC9D35EDA7A3DC21C729B9929024DB8B852DFDF102A086845702FD249EE43B54D2D033ABA95110C4"
                                                           + "F0A66EEAEE78F3C41D5D792A37D1D2299252A5498A44CA354F6F37FDC2F3B72B1A8378A5BA8B4997556E5A6F4125AD94"
                                                           + "6BD4FC402C4320B27111BC204B8B5448F43F7E77A8166A48137D85584BEFE2D9C85CCCD9BBF3F8A4E05930180AFDD697"
                                                           + "DA82ED9F1069150FFC76578C941CDBCC5BD2ECB7D6ABF9E68327DF51C26C8B42CB1DD8BDA98A82C4C6BA6A991E651BDF"
                                                           + "F68F0A62D5DBFEA020D4303E0C53D474CB11D553C5BEE1156917D72AC2A6CCC4EC1C775D41EE660E2485A45AF5A7CA08"
                                                           + "3DDDCC3EE4FFFC5E77BA97CC4473303C77D8B6FDB35E2A20627BEBBE327DD2D1AD1F880CA8EAE1E0067A9093929E5AB1"
                                                           + "8D406A518EDD8C1E0F0AB07736F55FCECF4A3B2ADCE1CE3E080B58DDF85A2262D0803A7E5B4E485E642BA533E2EC7A43"
                                                           + "F9E8DB20F75292ADAC704395469408C15641A9C28B83E8C1C799FAE0652F51369978F4C089FE15DD78C5F560CD28F5F7"
                                                           + "5FE0A39A60A61AEF6C7D802141E9809E7ACA68A38BE9BDF5312258704F8B11AF4262220CB55641FE95DF83EC9F786D6E"
                                                           + "69202C91EC4CAA4E38A21C3CC609C28B8F65552FE8334850858BBB30B837D874867EAD330A1F5B4D7F6BEC4748BE54A7"
                                                           + "82D5B21A192BC00A7F2240FBD900460785D1971A94C587493D21CDA249676EDAC6C865147E269488B9CA78FAEFDC778F"
                                                           + "F60E79735DD5539879182424B054FAE8A9E153BFFD6957C533AEDC105E43AD7626312C8D229327D3E72AA9644BF3E2C9"
                                                           + "A08ABF807CF3A472C7DAF0AC4290A9E8F88D07AE8FEDB8A4B218C3EBBDBE53882781F2DE034B17FEFE69302B4975CF43"
                                                           + "E03645DC53BD355AF988B3A3D2431BF9D9A865750051EED7BAEFD1BAD4939C7EC293509A5851A145F79DCBEEFD195571"
                                                           + "AC2172AC6036812B4DC8040D186B8984CF9DC24F8F765166C6B2E8389DD24ED63CEE951442861669BDA0622BD90B041D"
                                                           + "C477C01A0D95D547E07A892CE1F26275ABC6F97702E03B776E2CA71E3D0EBB88D1ADF591122E6F0EC95A6CFBB976AE64"
                                                           + "BD0C7F074CB6E78E644DEE8200E2D626435907B9134000DBC3B50271F5A8F254D2CF02DA039D458E80FA13A33567AA9B"
                                                           + "374B47B799D0FF1A14CA92A50EFA192EA1641FE29A380E11386528B7248D6DE6AA90E1C9744713B768264B72A13CCAA9"
                                                           + "4F3E19ADA5129E0D8155EC1B267E2CDC7F0E7A08F203D9A18F8C8D18529709EF746A21D5FEC36EB547A2FD4490092AD0"
                                                           + "F06C55EE0A1CB104E2C3C3CF2BCBCBFFEAEC744A13E37310962CE40E072E7ECAE223943A03002077D3D96C7B4C3FB1E2"
                                                           + "C9EE9C5222A63252F26372BC2BD94507CE5728CEB7A0AA33527E0662B4561D1BD255806450772EABB7ED40F787A2E3C6"
                                                           + "64FA6BC3BE9BCD84FC7B42F16F94CC56CFB67297E475177E19E51010CFB74BA996BA1C3D793EA010C99901E2223B375E"
                                                           + "364BA193772B329D5D05AED959EBB924B698F0657AF43EEE8E0D54D15C93511209AAA9E10251BF81AD8B467D8FAEE2A4"
                                                           + "40782C372F55A62CFEF408803E4B3BD8EFB94061EAB525BD31957779B89EB1C75AB97F278B3EAF99A05686E04873D7A6"
                                                           + "85868D1C0F4510ADAB0B267FE4D3CB70C35B295AFC671B60C6575B60EEB99756E7B204A24D7095DF277BE18668E0F1AA"
                                                           + "5621D16F204575F76C3B13385BAF61AFF7F36D56111FD88FF093BEC4FFC26BA63720660B5BD209A9C14C0AC6B4E08B38"
                                                           + "FF580C18E39A22A9AC36912892537B0FD42800445DBEF1A03D2D8624C1B125519927C282EEFAC4AFC16128B07456FBC9"
                                                           + "9D34C783AE08EBB0C46915971429FE64E448F1678BF76C7C20F91AD80E213E39AD89962AEA44E06EAB351C9B3A5859D5"
                                                           + "A884DE0CD767260CB60A96F508C62B731047CB1F3CA6AE28742771F4EC3BE45DF500F0132B6E947D2468AAB9410BC1F5"
                                                           + "81328471B3E53E8E29A0794F4EA8BDF9FDB3922CECBD2AAAF75A2AF4C7CEBA03382332D39DFB770559789708930E4C77"
                                                           + "966C7364E2A4D762C122BE3FCBD37276EA6194071BB7C18E2627524F3AB2BE7C0C6E59F62D1F075E1951DD3352F6CA97"
                                                           + "62F243F6691FE6A9DCE4278B178F688E433B990272000F23C92F74A1CFF1429BDF1C3FE1B9AA1C0E7A58ABFFBB54D3F3"
                                                           + "8ED93B11FB12233CFF48C812A227747849012F7BB85529D87459E11DCA9F7A9C3242054DB6BB93B48A47D69BA791B2A5"
                                                           + "D694A8776B22B8881BB2D192AB0A45AEC71A7171F844E3B1C4149D118EFA899E88D96A296D5EB811AF923AFD1A92E0C7"
                                                           + "1464B90C8E5EC24954FE8C9BFB518A308B3D301D8D6C62E5AD40F63BCE24699AF0BBD2E48FD9AA7C3A1C597731700E3D"
                                                           + "86E16AD36A67BC031BF381B82CF40B1B235F51727913BBC311A186FDC23EE267739740CC57C36BE05F9331EA40279C34"
                                                           + "C44FB8FDFCC7E9CDA54C394CEF9C17F8529A56E3BCCBA327CABD07F5F9C567B70DFBD9D7139E39B7E1A493482321B11C"
                                                           + "881BA9D44CBABEA64F1AF18C18B3B5F98FF4A95FD907E112AED857B033BB7E0FF9466CF5FC691CCC1142BFB8CE81BAD7"
                                                           + "DB554409B79E23D0A41063857E4AA05583525E69EDAA017F6A7FA96C25A38E7A7D01E22F96ADBB683B4EB8A487202426"
                                                           + "D68D297B30BE0A803D4FCA1E037DB3BD63A2F06EFD68BD4D7BEAD8338D36AC1425163B3C739B86AC9D967ED54DE24CA5"
                                                           + "8BC129CFF73585B667DC33F32BC4A4D9E106076849BC2574F0E5AB2C0B5CBDBCA59BB644BC86F3339B23B3B12959FC78"
                                                           + "87F7291136343E54F4A56C344DC5BE641DBCE62AED4D4BB958C4D54D7196DB4ACB8A1F43F88CDBB758546F44C5929350"
                                                           + "1E0569F00B97FC244507C248031D07EE4DBB6A97270B772791E758E582989D93124AB82F15A9DCA469C1A0E98CC75FF6"
                                                           + "83430036F16B4E94E94DECA06EBE7FE2B8E9C0A690AAD7A91877799FCF24CE275844A63E68F1A5C799BC83C7F5384CD9"
                                                           + "322E20B619D39D0031482FFED8224F6C522C8533CB29C04AF154D920D747D81616EA219E358385AA9FDB8E94A7EE5B53"
                                                           + "F2CC31B3A7BAC787E54AB9536FC42A3E369043C6F5C11D0F7D452852C3FB3F1845942186044385FB9E482962B1DAEBD2"
                                                           + "B3DF125D1A61843F71A272E3A1D97AAB97DE5831C56D16A6A6620F8C6CD0F4F1E41AFE6895BA3664D23A03EAB3531126"
                                                           + "E87335F4BCBBF2E39C47B5A58BA15066F79717D8296667553ECD0991F14D42F8934D753929F146E4B58D00A3E0139D66"));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void parameterNamesAndSizes(MLDSAParameterSets params) {
        assertSame(params, MLDSAParameterSets.fromJceName(params.getJceName()));
        assertSame(params, MLDSAParameterSets.fromJceName(params.getJceName().replace("-", "").toLowerCase(Locale.ROOT)));
        assertSame(params, MLDSAParameterSets.fromSshName(params.getSshName()));
        assertTrue(MLDSAParameterSets.SSH_NAMES.contains(params.getSshName()));
        switch (params) {
            case ML_DSA_44:
                assertEquals(1312, params.getPublicKeySize());
                assertEquals(17, params.getOid());
                break;
            case ML_DSA_65:
                assertEquals(1952, params.getPublicKeySize());
                assertEquals(18, params.getOid());
                break;
            case ML_DSA_87:
                assertEquals(2592, params.getPublicKeySize());
                assertEquals(19, params.getOid());
                break;
            default:
                fail("Unexpected ML-DSA parameters");
        }
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void providerServicesAndSignatureScope(MLDSAParameterSets params) throws Exception {
        assumeSupported(params);
        KeyFactory factory = SecurityUtils.getKeyFactory(params.getJceName());
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(params.getJceName());
        String expectedProvider = System.getProperty("mldsa.test.provider");
        if (expectedProvider != null) {
            assertEquals(expectedProvider, factory.getProvider().getName());
            assertEquals(expectedProvider, generator.getProvider().getName());
        }
        assertFalse(new SunSecurityProviderRegistrar().isSecurityEntitySupported(Signature.class, params.getJceName()));
        assertFalse(new BouncyCastleSecurityProviderRegistrar()
                .isSecurityEntitySupported(Signature.class, params.getJceName()));
    }

    @Test
    void sunRegistrarRejectsUnrelatedServices() {
        SunSecurityProviderRegistrar registrar = new SunSecurityProviderRegistrar();
        assertFalse(registrar.isSecurityEntitySupported(KeyFactory.class, "RSA"));
        assertFalse(registrar.isSecurityEntitySupported(KeyFactory.class, "EC"));
        assertFalse(registrar.isSecurityEntitySupported(KeyFactory.class, "Ed25519"));
        assertFalse(registrar.isSecurityEntitySupported(KeyPairGenerator.class, "RSA"));
        assertFalse(registrar.isSecurityEntitySupported(MessageDigest.class, "SHA-256"));
        assertFalse(registrar.isSecurityEntitySupported(Signature.class, "SHA256withRSA"));
        assertFalse(registrar.isSecurityEntitySupported(KeyFactory.class, "ML-DSA"));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void sunRegistrarKeyFactorySupport(MLDSAParameterSets params) {
        Provider provider = Security.getProvider("SUN");
        boolean available = provider != null && provider.getService("KeyFactory", params.getJceName()) != null;
        assertEquals(available,
                new SunSecurityProviderRegistrar().isSecurityEntitySupported(KeyFactory.class, params.getJceName()));
    }

    @Test
    void unknownNames() {
        assertNull(MLDSAParameterSets.fromJceName(null));
        assertNull(MLDSAParameterSets.fromSshName(null));
        assertNull(MLDSAParameterSets.fromJceName("ML-DSA"));
        assertNull(MLDSAParameterSets.fromJceName("ML-DSA-99"));
        assertNull(MLDSAParameterSets.fromSshName("ssh-mldsa-99"));
        assertNull(MLDSAParameterSets.fromSshName("ssh-rsa"));
        assertFalse(SecurityUtils.isMLDSASupported(null));
        assertFalse(SecurityUtils.isMLDSASupported("ML-DSA-99"));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void acvpPublicKey(MLDSAParameterSets params, String publicHex) throws Exception {
        assumeSupported(params);
        byte[] expected = hex(publicHex);
        assertEquals(params.getPublicKeySize(), expected.length);
        PublicKey key = MLDSAUtils.getPublicKey(params, expected.clone());
        assertSame(params, MLDSAUtils.getParameters(key));
        assertArrayEquals(expected, MLDSAUtils.getRawBytes(key));
        assertEquals(params.getSshName(), KeyUtils.getKeyType(key));
        assertEquals(params.getPublicKeySize() * Byte.SIZE, KeyUtils.getKeySize(key));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void decoderAndAuthorizedKeyRoundTrip(MLDSAParameterSets params, String publicHex) throws Exception {
        assumeSupported(params);
        PublicKey key = MLDSAUtils.getPublicKey(params, hex(publicHex));
        PublicKeyEntryDecoder decoder = KeyUtils.getPublicKeyEntryDecoder(params.getSshName());
        assertNotNull(decoder);
        assertSame(decoder, KeyUtils.getPublicKeyEntryDecoder(key));
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        assertEquals(params.getSshName(), decoder.encodePublicKey(encoded, key));
        PublicKey decoded = decoder.decodePublicKeyByType(null, params.getSshName(),
                new ByteArrayInputStream(encoded.toByteArray()), Collections.emptyMap());
        assertArrayEquals(hex(publicHex), MLDSAUtils.getRawBytes(decoded));
        String line = PublicKeyEntry.toString(key) + " ACVP test key";
        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(line);
        assertNotNull(entry);
        assertEquals(params.getSshName(), entry.getKeyType());
        assertArrayEquals(hex(publicHex),
                MLDSAUtils.getRawBytes(entry.resolvePublicKey(null, Collections.emptyMap(), null)));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void generatedKeyAndDecoderSize(MLDSAParameterSets params) throws Exception {
        assumeSupported(params);
        MLDSAPublicKeyDecoder decoder = new MLDSAPublicKeyDecoder(params);
        KeyPair pair = decoder.generateKeyPair(params.getPublicKeySize() * Byte.SIZE);
        assertSame(params, MLDSAUtils.getParameters(pair.getPublic()));
        assertSame(params, MLDSAUtils.getParameters(pair.getPrivate()));
        assertEquals(params.getPublicKeySize(), MLDSAUtils.getRawBytes(pair.getPublic()).length);
        assertThrows(InvalidKeySpecException.class, () -> decoder.generateKeyPair(params.getPublicKeySize()));
        assertThrows(InvalidKeySpecException.class, () -> decoder.generateKeyPair(256));
        MLDSAParameterSets other
                = params == MLDSAParameterSets.ML_DSA_44 ? MLDSAParameterSets.ML_DSA_65 : MLDSAParameterSets.ML_DSA_44;
        assertThrows(InvalidKeySpecException.class, () -> decoder.generateKeyPair(other.getPublicKeySize() * Byte.SIZE));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void malformedRawLengths(MLDSAParameterSets params) {
        for (int size : new int[] { 0, params.getPublicKeySize() - 1, params.getPublicKeySize() + 1 }) {
            assertThrows(InvalidKeySpecException.class, () -> MLDSAUtils.getPublicKey(params, new byte[size]));
        }
        assertThrows(InvalidKeySpecException.class, () -> MLDSAUtils.getPublicKey(params, null));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void decoderRejectsMismatchedUnknownAndTruncated(MLDSAParameterSets params, String publicHex)
            throws Exception {
        assumeSupported(params);
        MLDSAParameterSets other
                = params == MLDSAParameterSets.ML_DSA_44 ? MLDSAParameterSets.ML_DSA_65 : MLDSAParameterSets.ML_DSA_44;
        MLDSAPublicKeyDecoder decoder = new MLDSAPublicKeyDecoder(params);
        PublicKey key = MLDSAUtils.getPublicKey(params, hex(publicHex));
        assertThrows(IOException.class, () -> new MLDSAPublicKeyDecoder(other)
                .encodePublicKey(new ByteArrayOutputStream(), key));
        ByteArrayBuffer raw = new ByteArrayBuffer();
        raw.putBytes(hex(publicHex));
        byte[] encoded = raw.getCompactData();
        assertThrows(InvalidKeySpecException.class, () -> decoder.decodePublicKey(null,
                other.getSshName(), new ByteArrayInputStream(encoded), Collections.emptyMap()));
        assertThrows(InvalidKeySpecException.class, () -> decoder.decodePublicKey(null,
                "ssh-mldsa-99", new ByteArrayInputStream(encoded), Collections.emptyMap()));
        assertThrows(IOException.class, () -> decoder.decodePublicKey(null, params.getSshName(),
                new ByteArrayInputStream(Arrays.copyOf(encoded, encoded.length - 1)), Collections.emptyMap()));
        ByteArrayBuffer wrongLength = new ByteArrayBuffer();
        wrongLength.putBytes(new byte[params.getPublicKeySize() - 1]);
        assertThrows(InvalidKeySpecException.class, () -> decoder.decodePublicKey(null, params.getSshName(),
                new ByteArrayInputStream(wrongLength.getCompactData()), Collections.emptyMap()));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void malformedSubjectPublicKeyInfo(MLDSAParameterSets params, String publicHex) throws Exception {
        assumeSupported(params);
        byte[] encoded = MLDSAUtils.getPublicKey(params, hex(publicHex)).getEncoded();
        assertThrows(InvalidKeySpecException.class, () -> MLDSAUtils.getRawBytes(
                encodedPublicKey(params.getJceName(), Arrays.copyOf(encoded, encoded.length - 1))));
        assertThrows(InvalidKeySpecException.class, () -> MLDSAUtils.getRawBytes(
                encodedPublicKey(params.getJceName(), Arrays.copyOf(encoded, encoded.length + 1))));
        byte[] indefinite = encoded.clone();
        indefinite[1] = (byte) 0x80;
        assertThrows(InvalidKeySpecException.class,
                () -> MLDSAUtils.getRawBytes(encodedPublicKey(params.getJceName(), indefinite)));
        byte[] nonMinimal = new byte[encoded.length + 1];
        nonMinimal[0] = 0x30;
        nonMinimal[1] = (byte) 0x83;
        System.arraycopy(encoded, 2, nonMinimal, 3, encoded.length - 2);
        assertThrows(InvalidKeySpecException.class,
                () -> MLDSAUtils.getRawBytes(encodedPublicKey(params.getJceName(), nonMinimal)));
        MLDSAParameterSets other
                = params == MLDSAParameterSets.ML_DSA_44 ? MLDSAParameterSets.ML_DSA_65 : MLDSAParameterSets.ML_DSA_44;
        assertThrows(InvalidKeySpecException.class,
                () -> MLDSAUtils.getRawBytes(encodedPublicKey(other.getJceName(), encoded)));
        assertThrows(InvalidKeySpecException.class,
                () -> MLDSAUtils.getRawBytes(encodedPublicKey(params.getJceName(), null)));
    }

    private static PublicKey encodedPublicKey(String algorithm, byte[] encoded) {
        return new PublicKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return algorithm;
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return encoded;
            }
        };
    }

    private static void assumeSupported(MLDSAParameterSets params) {
        Assumptions.assumeTrue(SecurityUtils.isMLDSASupported(params.getJceName()), "ML-DSA provider unavailable");
    }

    private static byte[] hex(String value) {
        return BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, value);
    }
}
