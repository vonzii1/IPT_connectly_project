from ..models import Comment

class CommentFactory:
    @staticmethod
    def create_comment(author, post, text):
        return Comment.objects.create(
            author=author,
            post=post,
            text=text
        )

    @staticmethod
    def update_comment(comment, text):
        comment.text = text
        comment.save()
        return comment