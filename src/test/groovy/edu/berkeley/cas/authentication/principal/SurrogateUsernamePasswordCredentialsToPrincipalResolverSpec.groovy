package edu.berkeley.cas.authentication.principal

import edu.berkeley.cas.authentication.handler.SurrogateUsernamePasswordAuthenticationHandler
import org.jasig.cas.authentication.principal.Credentials
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials
import spock.lang.Specification
import spock.lang.Unroll

class SurrogateUsernamePasswordCredentialsToPrincipalResolverSpec extends Specification {
    @Unroll
    def "test supports"() {
        expect:
        a.supports(b) == c
        where:
        a                                                                           | b                                                    | c
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver()               | [:] as Credentials                                   | false
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver()               | new UsernamePasswordCredentials(username: "test")    | false
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver()               | new UsernamePasswordCredentials(username: "test+me") | true
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver(separator: '-') | new UsernamePasswordCredentials(username: "test-me") | true
    }

    @Unroll
    def "test extract principal Id"() {
        expect:
        a.extractPrincipalId(b) == c
        where:
        a                                                                           | b                                                    | c
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver()               | new UsernamePasswordCredentials(username: "test+me") | "me"
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver(separator: '-') | new UsernamePasswordCredentials(username: "test-me") | "me"
    }
}
