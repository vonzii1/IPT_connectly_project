from ..models import Like

class LikeFactory:
    @staticmethod
    def create_like (author, post):
        return Like.objects.create(author=author, post=post)
    