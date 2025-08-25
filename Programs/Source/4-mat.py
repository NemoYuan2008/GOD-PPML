from Compiler.types import sfix, Matrix


x = [sfix(i) for i in range(128)]
x_mat = [x for i in range(128)]
x_mat = Matrix.create_from(x_mat)
x_mat.dot(x_mat)
