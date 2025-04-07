from ..models import Post

class PostFactory:
    @staticmethod
    def create_post(author, post_type, title, content, metadata, private=False):  # ✅ include 'private'
        return Post.objects.create(
            author=author,
            post_type=post_type,
            title=title,
            content=content,
            metadata=metadata,
            private=private  
        )