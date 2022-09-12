package no.cantara.security.authentication.whydah;

import net.whydah.sso.application.mappers.ApplicationTokenMapper;
import net.whydah.sso.application.types.ApplicationToken;
import net.whydah.sso.application.types.Tag;
import net.whydah.sso.user.mappers.UserTokenMapper;
import net.whydah.sso.user.types.UserApplicationRoleEntry;
import net.whydah.sso.user.types.UserToken;
import net.whydah.sso.whydah.DEFCON;
import no.cantara.stingray.security.authentication.*;
import no.cantara.stingray.security.authentication.whydah.StingrayWhydahService;
import no.cantara.stingray.security.authentication.whydah.WhydahStingrayAuthenticationManager;
import no.cantara.stingray.security.authentication.whydah.WhydahStingrayAuthenticationManagerFactory;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class StingrayWhydahAuthenticationManagerTest {

    final String USERTOKEN_ID = UUID.randomUUID().toString();
    final String USERTICKET = UUID.randomUUID().toString();

    final String appTokenXml = String.format("<applicationtoken>\n" +
            "     <params>\n" +
            "         <applicationtokenID>2c14bf76cc4a78078bf216a815ed5cd1</applicationtokenID>\n" +
            "         <applicationid>899e0ae9b790765998c99bbe5</applicationid>\n" +
            "         <applicationname>Observation Flowtest</applicationname>\n" +
            "         <applicationtags>HIDDEN, JURISDICTION_NORWAY, My!uTag_Val!uue</applicationtags>\n" +
            "         <expires>%s</expires>\n" +
            "     </params> \n" +
            "     <Url type=\"application/xml\" method=\"POST\"                 template=\"https://entrasso-qa.entraos.io/tokenservice/user/2c14bf76cc4a78078bf216a815ed5cd1/get_usertoken_by_usertokenid\"/> \n" +
            " </applicationtoken>", System.currentTimeMillis() + 60 * 60 * 1000);

    final String jwtTokenWithAppToken = "eyJ0eXAiOiJKV1QiLCJraWQiOiJkOWRkMzdjNjhkNTU4ZWVlOTg2NmNkYTliYjM5ZWY4NiIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJUU0oxVnh0UEU0X3dSemlUbTRBWHVtMGZKSTVfMEZWS0xpXzhqZHprWU53LSIsImF1ZCI6IlRTSjFWeHRQRTRfd1J6aVRtNEFYdW0wZkpJNV8wRlZLTGlfOGpkemtZTnctIiwiYXBwX25hbWUiOiJSZWx5bmtRQSIsImFwcF91cmwiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJhcHBfdG9rZW4iOiJiZjU5NTM5MzBkM2M5MjQ1ZDRkMGJlMzc1YTNlNTI3ZCIsImlzcyI6Imh0dHBzOi8vZW50cmFzc28tcWEuZW50cmFvcy5pby9vYXV0aDIiLCJleHAiOjE2Nzg1MjI2ODEsIm5vbmNlIjoiIiwiYXBwX2lkIjoiMDkwMGRkYTYyNjcyM2M2YmZjZTZlZTU0ZiIsImlhdCI6MTY2Mjk3MDU5MSwianRpIjoiZDYzYjA3ZTktMmRkZi00ZWFmLWI4YjctMTE0ZGE1MmZlOTJhIn0.T1P0i-iuSjTEQeSTUYgptEw8HUpOLMSXaagDC0HrmE_fPJHsIx4Enk-CfSV6ATAp3opycu5CEUueC31jCAKgu1rmwGsZBpB9Loii9h472oKtj2LXZb-j6jJ71xRBDbaxP-d_ekzsbkV5J_iOez5XrtrZG3CvVN2ktBj0G5rGm73r-Oxjbdi_ZRmO17c4EzoW3x1fJQ23bvtTJ9a6RST2Q-z6tNozq2Dt84ecFZfslJm_xlOoiy4F5ytmkUVO9CWKd1dkcG8RknMKFzWu2yNluGGwpC7MJr5eE3WqlDB2Q-hF2ln1OQeGazKYG5qS4yDBuIb7DGXoCmhebp_SmTzbXA";
    final ApplicationToken applicationToken = ApplicationTokenMapper.fromXml(appTokenXml);

    @Test
    public void thatAppTokenXmlIsRecognizedAsApplication() {
        StingrayAuthenticationManager authenticationManager = new WhydahStingrayAuthenticationManager(
                "", () -> "", new TestWhydahService(), WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_USER_ROLE_NAME_FIX, WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_APPLICATION_TAG_NAME
        );
        StingrayAuthenticationResult authenticationResult = authenticationManager.authenticate("Bearer " + appTokenXml);
        assertTrue(authenticationResult.isValid());
        assertTrue(authenticationResult.isApplication());
        StingrayApplicationAuthentication applicationAuthentication = authenticationResult.application().get();
        assertEquals("testapp", applicationAuthentication.ssoId());
        assertEquals(3, applicationAuthentication.tags().size());
        assertEquals(Tag.DEFAULTNAME, applicationAuthentication.tags().get(0).getName());
        assertEquals("HIDDEN", applicationAuthentication.tags().get(0).getValue());
        assertEquals("JURISDICTION", applicationAuthentication.tags().get(1).getName());
        assertEquals("NORWAY", applicationAuthentication.tags().get(1).getValue());
        assertEquals("My_Tag", applicationAuthentication.tags().get(2).getName());
        assertEquals("Val_ue", applicationAuthentication.tags().get(2).getValue());
    }

    @Test
    public void thatAppTokenIdIsRecognizedAsApplication() {
        StingrayAuthenticationManager authenticationManager = new WhydahStingrayAuthenticationManager(
                "", () -> "", new TestWhydahService(), WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_USER_ROLE_NAME_FIX, WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_APPLICATION_TAG_NAME
        );
        StingrayAuthenticationResult authenticationResult = authenticationManager.authenticate("Bearer " + applicationToken.getApplicationTokenId());
        assertTrue(authenticationResult.isValid());
        assertTrue(authenticationResult.isApplication());
        StingrayApplicationAuthentication applicationAuthentication = authenticationResult.application().get();
        assertEquals("testapp", applicationAuthentication.ssoId());
        assertEquals(3, applicationAuthentication.tags().size());
        assertEquals(Tag.DEFAULTNAME, applicationAuthentication.tags().get(0).getName());
        assertEquals("HIDDEN", applicationAuthentication.tags().get(0).getValue());
        assertEquals("JURISDICTION", applicationAuthentication.tags().get(1).getName());
        assertEquals("NORWAY", applicationAuthentication.tags().get(1).getValue());
        assertEquals("My_Tag", applicationAuthentication.tags().get(2).getName());
        assertEquals("Val_ue", applicationAuthentication.tags().get(2).getValue());
    }

    @Test
    public void thatJwtTokenWithAppTokenIdIsRecognizedAsApplication() {
        StingrayAuthenticationManager authenticationManager = new WhydahStingrayAuthenticationManager(
                "https://entrasso-qa.entraos.io/oauth2", () -> "", new TestWhydahService(), WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_USER_ROLE_NAME_FIX, WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_APPLICATION_TAG_NAME
        );
        StingrayAuthenticationResult authenticationResult = authenticationManager.authenticate("Bearer " + jwtTokenWithAppToken);
        assertTrue(authenticationResult.isValid());
        assertTrue(authenticationResult.isApplication());
        StingrayApplicationAuthentication applicationAuthentication = authenticationResult.application().get();
        assertEquals("testapp_jwt", applicationAuthentication.ssoId());
        assertEquals(3, applicationAuthentication.tags().size());
        assertEquals(Tag.DEFAULTNAME, applicationAuthentication.tags().get(0).getName());
        assertEquals("HIDDEN", applicationAuthentication.tags().get(0).getValue());
        assertEquals("JURISDICTION", applicationAuthentication.tags().get(1).getName());
        assertEquals("NORWAY", applicationAuthentication.tags().get(1).getValue());
        assertEquals("My_Tag", applicationAuthentication.tags().get(2).getName());
        assertEquals("Val_ue", applicationAuthentication.tags().get(2).getValue());
    }

    @Test
    public void thatUserTicketIsRecognizedAsUser() {
        StingrayAuthenticationManager authenticationManager = new WhydahStingrayAuthenticationManager(
                "", () -> "", new TestWhydahService(), WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_USER_ROLE_NAME_FIX, WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_APPLICATION_TAG_NAME
        );

        StingrayAuthenticationResult authenticationResult = authenticationManager.authenticate("Bearer " + USERTICKET);
        assertTrue(authenticationResult.isValid());
        assertTrue(authenticationResult.isUser());
        StingrayUserAuthentication userAuthentication = authenticationResult.user().get();

        assertEquals("MyUUIDValue", userAuthentication.ssoId());
        assertEquals(2, userAuthentication.groups().size());
        Set<String> groups = new LinkedHashSet<>(userAuthentication.groups());
        assertTrue(groups.contains("post"));
        assertTrue(groups.contains("pre"));
    }

    @Test
    public void thatAdditionalFieldsFromUserTokenAreAvailable() {
        StingrayAuthenticationManager authenticationManager = new WhydahStingrayAuthenticationManager(
                "", () -> "", new TestWhydahService(), WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_USER_ROLE_NAME_FIX, WhydahStingrayAuthenticationManagerFactory.DEFAULT_AUTH_GROUP_APPLICATION_TAG_NAME
        );

        StingrayAuthenticationResult authenticationResult = authenticationManager.authenticate("Bearer " + USERTICKET);
        assertTrue(authenticationResult.isValid());
        assertTrue(authenticationResult.isUser());
        StingrayUserAuthentication userAuthentication = authenticationResult.user().get();

        assertEquals("MyUUIDValue", userAuthentication.ssoId());
        assertEquals(2, userAuthentication.groups().size());
        Set<String> groups = new LinkedHashSet<>(userAuthentication.groups());
        assertTrue(groups.contains("post"));
        assertTrue(groups.contains("pre"));

        assertEquals("Ola", userAuthentication.firstName());
        assertEquals("Nordmann", userAuthentication.lastName());
        assertEquals("Ola Nordmann", userAuthentication.fullName());
        assertEquals("test@whydah.net", userAuthentication.email());
        assertEquals("+4712345678", userAuthentication.cellPhone());
        assertEquals(5, userAuthentication.securityLevel());
        long estimatedExpiry = Instant.now().plus(3000, ChronoUnit.MILLIS).toEpochMilli();
        long expiryDelta = Math.abs(estimatedExpiry - userAuthentication.tokenExpiry().toEpochMilli());
        int expiryEstimationTolerance = 2000; // 2 seconds tolerance
        assertTrue(expiryDelta < expiryEstimationTolerance); // check that actual expiry within tolerance of estimated expiry
    }

    private class TestWhydahService implements StingrayWhydahService {
        @Override
        public UserToken findUserTokenFromUserTokenId(String userTokenId) {
            return null;
        }

        @Override
        public String getUserTokenByUserTicket(String userticket) {
            if (USERTICKET.equals(userticket)) {
                UserToken userToken = new UserToken();
                userToken.setUid("MyUUIDValue");
                userToken.setUserName("ola");
                userToken.setCellPhone("+4712345678");
                userToken.setSecurityLevel("5");
                userToken.setNs2link("");
                userToken.setFirstName("Ola");
                userToken.setEmail("test@whydah.net");
                userToken.setLastName("Nordmann");
                userToken.setTimestamp(String.valueOf(System.currentTimeMillis()));
                userToken.setLifespan("3000");
                userToken.setPersonRef("73637276722376");
                userToken.setDefcon(DEFCON.DEFCON5.toString());
                userToken.setUserTokenId(USERTOKEN_ID);
                userToken.setEncryptedSignature("");
                userToken.setEmbeddedPublicKey("");
                List<UserApplicationRoleEntry> roleList = new LinkedList<>();
                roleList.add(new UserApplicationRoleEntry("MyUUIDValue", "testapp", "Test-Application", "Cantara", "access-groups-post", "post"));
                roleList.add(new UserApplicationRoleEntry("MyUUIDValue", "testapp", "Test-Application", "Cantara", "pre-access-groups", "pre"));
                userToken.setRoleList(roleList);
                String xml = UserTokenMapper.toXML(userToken);
                return xml;
            }
            return null;
        }

        @Override
        public String getApplicationIdFromApplicationTokenId(String applicationTokenId) {
            if ("2c14bf76cc4a78078bf216a815ed5cd1".equals(applicationTokenId)) {
                return "testapp";
            }
            if ("bf5953930d3c9245d4d0be375a3e527d".equals(applicationTokenId)) {
                return "testapp_jwt";
            }
            return null;
        }

        @Override
        public List<StingrayApplicationTag> getApplicationTagsFromApplicationTokenId(String applicationTokenId) {
            if ("2c14bf76cc4a78078bf216a815ed5cd1".equals(applicationTokenId) || "bf5953930d3c9245d4d0be375a3e527d".equals(applicationTokenId)) {
                return applicationToken.getTags().stream()
                        .map(tag -> new StingrayApplicationTag(tag.getName(), tag.getValue()))
                        .collect(Collectors.toList());
            }
            return Collections.emptyList();
        }

        @Override
        public String createTicketForUserTokenID(String userTokenId) {
            return null;
        }

        @Override
        public boolean validateUserTokenId(String usertokenid) {
            if (USERTOKEN_ID.equals(usertokenid)) {
                return true;
            }
            return false;
        }
    }
}
