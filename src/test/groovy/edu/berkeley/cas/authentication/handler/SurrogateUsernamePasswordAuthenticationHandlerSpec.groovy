package edu.berkeley.cas.authentication.handler

import edu.berkeley.cas.authentication.principal.SurrogateUsernamePasswordCredentials
import edu.berkeley.cas.authentication.service.SurrogateUsernamePasswordService
import org.jasig.cas.authentication.handler.AuthenticationHandler
import org.jasig.cas.authentication.handler.BadUsernameOrPasswordAuthenticationException
import org.jasig.cas.authentication.principal.Credentials
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class SurrogateUsernamePasswordAuthenticationHandlerSpec extends Specification {
    @Shared
    SurrogateUsernamePasswordAuthenticationHandler surrogateUsernamePasswordAuthenticationHandler

    void setupSpec() {
        surrogateUsernamePasswordAuthenticationHandler = new SurrogateUsernamePasswordAuthenticationHandler(
                surrogateUsernamePasswordService: [canAuthenticateAs: { target, surrogate ->
                    return true
                }] as SurrogateUsernamePasswordService,
                authenticationHandlerList: [
                        [
                                authenticate: { it.username == it.password },
                                supports    : { return UsernamePasswordCredentials.isAssignableFrom(it.class) }
                        ] as AuthenticationHandler
                ]
        )
    }

    @Unroll
    def "test supports"() {
        expect:
        surrogateUsernamePasswordAuthenticationHandler.supports(a) == b
        where:
        a                                                                                                      | b
        [] as Credentials                                                                                      | false
        new UsernamePasswordCredentials(username: "test", password: "test")                                    | false
        new SurrogateUsernamePasswordCredentials(username: "test", targetUsername: "target", password: "test") | true
    }

    @Unroll
    def "test authenticate"() {
        expect:
        surrogateUsernamePasswordAuthenticationHandler.authenticate(a) == b
        where:
        a                                                                    | b
        new SurrogateUsernamePasswordCredentials(username: "me", targetUsername: "test", password: "me") | true
    }

    @Unroll
    def "bad authentication"() {
        when:
        surrogateUsernamePasswordAuthenticationHandler.authenticate(new SurrogateUsernamePasswordCredentials(username: "me", targetUsername: "test", password: "wrong"))
        then:
        thrown BadSurrogateAuthenticationException
    }
}
