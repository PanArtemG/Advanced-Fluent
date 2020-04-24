import Vapor
import Crypto
import Fluent

struct UsersController: RouteCollection {
    func boot(router: Router) throws {
        let usersRoute = router.grouped("api", "users")
        usersRoute.get(use: getAllHandler)
        usersRoute.get(User.parameter, use: getHandler)
        usersRoute.get(User.parameter, "acronyms", use: getAcronymsHandler)
        
        let basicAuthMiddleware = User.basicAuthMiddleware(using: BCryptDigest())
        let basicAuthGroup = usersRoute.grouped(basicAuthMiddleware)
        basicAuthGroup.post("login", use: loginHandler)
        
        let tokenAuthMiddleware = User.tokenAuthMiddleware()
        let guardAuthMiddleware = User.guardAuthMiddleware()
        let tokenAuthGroup = usersRoute.grouped(tokenAuthMiddleware, guardAuthMiddleware)
        
        tokenAuthGroup.post(User.self, use: createHandler)
        tokenAuthGroup.delete(User.parameter, use: deleteHandler)
        tokenAuthGroup.post( UUID.parameter, "restore", use: restoreHandler)
        
        
    }
    
    func createHandler(_ req: Request, user: User) throws -> Future<User.Public> {
        user.password = try BCrypt.hash(user.password)
        return user.save(on: req).convertToPublic()
    }
    
    func getAllHandler(_ req: Request) throws -> Future<[User.Public]> {
        return User.query(on: req).decode(data: User.Public.self).all()
    }
    
    func getHandler(_ req: Request) throws -> Future<User.Public> {
        return try req.parameters.next(User.self).convertToPublic()
    }
    
    func getAcronymsHandler(_ req: Request) throws -> Future<[Acronym]> {
        return try req.parameters.next(User.self).flatMap(to: [Acronym].self) { user in
            try user.acronyms.query(on: req).all()
        }
    }
    
    func loginHandler(_ req: Request) throws -> Future<Token> {
        let user = try req.requireAuthenticated(User.self)
        let token = try Token.generate(for: user)
        return token.save(on: req)
    }
    
    func deleteHandler(_ req: Request)
        throws -> Future<HTTPStatus> {
            return try req.parameters
                .next(User.self)
                .delete(on: req)
                .transform(to: .noContent)
    }
    
    func restoreHandler(_ req: Request)
        throws -> Future<HTTPStatus> {
            // 1
            let userID = try req.parameters.next(UUID.self)
            // 2
            return User.query(on: req, withSoftDeleted: true)
                .filter(\.id == userID)
                .first().flatMap(to: HTTPStatus.self) { user in
                    // 3
                    guard let user = user else {
                        throw Abort(.notFound)
                    }
                    // 4
                    return user.restore(on: req).transform(to: .ok)
            }
    }
}
