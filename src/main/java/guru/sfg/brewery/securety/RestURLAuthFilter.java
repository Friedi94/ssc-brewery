package guru.sfg.brewery.securety;

import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class RestURLAuthFilter extends AbsractRestAuthFilter{

    public RestURLAuthFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    protected String getPassword(HttpServletRequest request) {
        return request.getParameter("Api-Secret");
    }

    protected String getUsername(HttpServletRequest request) {
        return request.getParameter("Api-Key");
    }
}
