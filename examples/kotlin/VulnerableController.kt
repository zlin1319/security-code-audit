import java.net.URL
import java.security.MessageDigest
import java.util.Random

class VulnerableController {
    fun run(user: String, url: String, cmd: String, response: javax.servlet.http.HttpServletResponse) {
        val query = "SELECT * FROM users WHERE name = '" + user + "'"
        println(query)

        response.writer.write("<div>" + user + "</div>")
        Runtime.getRuntime().exec("sh -c " + cmd)

        URL(url).openConnection()

        val digest = MessageDigest.getInstance("MD5")
        val token = Random().nextInt()
        val apiKey = "super-secret-key"

        println(digest)
        println(token)
        println(apiKey)
    }
}
