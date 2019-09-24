//jwt이 유효한지 검증
//JWT 모듈을 추가한다.
const jwt = require('jsonwebtoken');

//JWT토큰 유효성 검사 공통 모듈
exports.verifyToken = (req,res,next)=>{
    try {
        //jwt.verify('브라우저에서 전달되는 토큰','서버에 저장해둔 토큰발급 인증키값') 메소드로 토큰 유효성을 검사한다. 
        //jwt.verify메소드는 실행 후 토큰 내 페이로드에 저장되어 있는 사용자정보를 디코딩해서 반환합니다.
        //검사 후 반환되는 디코디드된 사용자 저장값을 req.decoded에 저장 
        req.decoded = jwt.verify(req.headers.authorization,process.env.JWT_SECRET);
        console.log("req.decode", req.decoded);
        //id, email, username

        return next();
    } catch(err){
        //파기기한이 지난 토큰인 경우 
        if (err.name === 'TokenExpiredError') {
            return res.status(419).json({
                code:419,
                message:'인증 토큰이 만료되었습니다.'
            });
        }

        return res.status(401).json({
            code:401,
            message:'유효하지 않은 토큰입니다.'
        });
    }
};
